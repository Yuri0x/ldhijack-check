#!/usr/bin/env bash
# ldhijack-check.sh — Linux 动态链接器劫持排查（只读，Linux/glibc 或 musl）
# 覆盖：ld.so.preload / ld.so.conf.d 路径劫持 / LD_PRELOAD 环境变量持久化 / 运行时内存映射
# 退出码：0 干净  1 有告警  2 有严重项
#
# usage:
#   ./ldhijack-check.sh                 # 完整检查
#   ./ldhijack-check.sh --prevail       # 只做与包管理器无关的检查（更快）
#   ./ldhijack-check.sh --save-baseline # 保存当前"干净基线"到 $BASE
#   ./ldhijack-check.sh --diff-baseline # 与基线对比，报告新增项

set -uo pipefail
V=0
BASE=${LDHIJACK_BASELINE:-/var/lib/ldhijack/baseline.txt}
MODE=scan
DEEP=1
for a in "$@"; do
  case "$a" in
    -v|--verbose) V=1 ;;
    --save-baseline) MODE=save ;;
    --diff-baseline) MODE=diff ;;
    --deep) DEEP=1 ;;
    --no-deep) DEEP=0 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
  esac
done

CRIT=0; WARN=0
c_red=$'\033[31m'; c_yel=$'\033[33m'; c_grn=$'\033[32m'; c_dim=$'\033[2m'; c_off=$'\033[0m'
[ -t 1 ] || { c_red=; c_yel=; c_grn=; c_dim=; c_off=; }

crit() { CRIT=$((CRIT+1)); printf '%s[CRIT]%s %s\n' "$c_red" "$c_off" "$*"; }
warn() { WARN=$((WARN+1)); printf '%s[WARN]%s %s\n' "$c_yel" "$c_off" "$*"; }
info() { printf '%s[INFO]%s %s\n' "$c_dim" "$c_off" "$*"; }
ok()   { printf '%s[ OK ]%s %s\n' "$c_grn" "$c_off" "$*"; }
hdr()  { printf '\n=== %s ===\n' "$*"; }

# ---------- 工具与平台 ----------
PKG=""
command -v dpkg-query >/dev/null && PKG=dpkg
[ -z "$PKG" ] && command -v rpm >/dev/null && PKG=rpm
[ -z "$PKG" ] && command -v pacman >/dev/null && PKG=pacman

# 判定"文件是否由发行版包管理器负责"
pkg_owned() { # $@ = 路径列表；每行输出 owned / unowned / unknown
  local p
  case "$PKG" in
    dpkg) dpkg-query -S "$@" 2>/dev/null | awk -F': ' '{print $NF}' ;;
    rpm)  rpm -qf "$@" 2>/dev/null | grep -v 'is not owned by any package' ;;
    pacman) for p in "$@"; do pacman -Qo "$p" >/dev/null 2>&1 && echo "$p"; done ;;
    *) return ;;
  esac
}
pkg_check_available() { [ -n "$PKG" ] && [ "$MODE" = scan ]; }

# 判断是不是真的 ELF 共享对象（避免 *.so* 把 .socket / .sock 这类文件也算进来）
is_elf() { [ "$(head -c4 "$1" 2>/dev/null | od -An -tx1 | tr -d ' \n')" = "7f454c46" ]; }
# 标准库目录前缀（白名单）
STD_PREFIX_RE='^(/lib|/usr/lib|/lib64|/usr/lib64|/usr/local/lib)(/|$)'
is_std() { [[ "${1%/}" =~ $STD_PREFIX_RE ]]; }
is_volatile_dir() { [[ "${1%/}" =~ ^(/tmp|/var/tmp|/dev/shm|/run|/home|/root|/var/lib/.*/tmp)(/|$) ]]; }
# 判断一个二进制是不是静态链接（静态二进制不会被 ld.so.preload 污染，可做"可信读取器"）
is_static_bin() {
  if command -v file >/dev/null 2>&1; then file -b "$1" 2>/dev/null | grep -qi 'statically linked'; return $?; fi
  if command -v readelf >/dev/null 2>&1; then [ "$(readelf -d "$1" 2>/dev/null | grep -c NEEDED)" -eq 0 ]; return $?; fi
  ldd "$1" 2>&1 | grep -qi 'not a dynamic'; return $?
}
# usrmerge：dpkg 数据库记的是 /lib/...，而 /proc/maps 里是 /usr/lib/...，两个形式都要试
norm_alt() { printf '%s' "$1" | sed -e 's|^/usr/lib/|/lib/|' -e 's|^/usr/lib64/|/lib64/|'; }

# 收集自检
SELF_MAPS=$(cat /proc/self/maps 2>/dev/null | awk '{print $NF}')
SELF_PRELOADED=$(printf '%s\n' "$SELF_MAPS" | grep -cE '\.so' || true)

hdr "0. 前置自检"
info "主机: $(uname -n) | 内核: $(uname -r) | libc: $( (ldd --version 2>/dev/null || echo '?') | head -1)"
info "包管理器: ${PKG:-未识别（将跳过归属校验）}"
if [ -s /etc/ld.so.preload ]; then
  warn "本机存在非空 /etc/ld.so.preload —— 本脚本自身及其调用的所有动态链接工具"\
"都已加载该库，读数可能被篡改（见第 7 节反隐藏交叉验证）"
fi
[ -n "${LD_PRELOAD:-}" ] && crit "当前环境带 LD_PRELOAD=$LD_PRELOAD（会污染本次所有检查结果）"
[ -z "${LD_PRELOAD:-}" ] && ok "当前 shell 环境无 LD_PRELOAD"
info "本进程已加载 $(printf '%s\n' "$SELF_MAPS" | grep -c '\.so') 个 .so"

# ---------- 1. /etc/ld.so.preload ----------
hdr "1. /etc/ld.so.preload（全系统预加载，最高危）"
PRELOAD_ENTRIES=()
if [ ! -e /etc/ld.so.preload ]; then
  ok "不存在（默认状态）"
elif [ ! -s /etc/ld.so.preload ]; then
  ok "存在但为空"
else
  crit "/etc/ld.so.preload 非空，内容如下："
  while IFS= read -r line; do
    [ -z "${line// }" ] && continue
    [[ "$line" =~ ^# ]] && { info "注释: $line"; continue; }
    PRELOAD_ENTRIES+=("$line")
    if [ -e "$line" ]; then
      printf '        %s  [%s %s %s]\n' "$line" "$(stat -c '%s bytes' "$line")" \
        "$(stat -c '%U:%G %a' "$line")" "$(stat -c 'mtime %y' "$line" | cut -d. -f1)"
    else
      printf '        %s  [文件不存在]\n' "$line"
    fi
  done < <( { cat /etc/ld.so.preload; } 2>/dev/null )
  if [ "${#PRELOAD_ENTRIES[@]}" -eq 0 ]; then
    crit "文件声明有内容（stat 看得到大小）却一条也读不出来：存在读取路径 hook 的强烈迹象"
    crit "请改用静态二进制或离线介质核对：busybox cat /etc/ld.so.preload / 挂盘到另一台机器"
  fi
  stat -c '        文件属性: %U:%G %a mtime %y' /etc/ld.so.preload | cut -d. -f1
  if pkg_check_available; then
    for e in "${PRELOAD_ENTRIES[@]}"; do
      o=$(pkg_owned "$e")
      [ -z "$o" ] && crit "  $e 不属于任何发行版包（第三方/投放物）"
    done
  fi
fi

# ---------- 2. ld.so.conf / ld.so.conf.d ----------
hdr "2. 动态链接器搜索路径（ld.so.conf / ld.so.conf.d / ld.so.cache）"
CONF_DIRS=()
if [ -d /etc/ld.so.conf.d ]; then
  for f in /etc/ld.so.conf.d/*.conf; do
    [ -e "$f" ] || continue
    while read -r d; do
      d="${d%%#*}"; d="${d//[[:space:]]/}"; d="${d%/}"
      [ -z "$d" ] && continue
      CONF_DIRS+=("$d")
      if is_volatile_dir "$d"; then
        crit "$f 将易失目录加入库搜索路径: $d"
      elif ! is_std "$d"; then
        warn "$f 增加了非标准搜索路径: $d"
      fi
      if pkg_check_available; then
        [ -z "$(pkg_owned "$f")" ] && crit "$f 不属于任何发行版包（疑似投放物）"
      fi
      if [ -d "$d" ] && ! is_std "$d"; then
        [ -w "$d" ] && [ "$(stat -c '%U' "$d" 2>/dev/null)" != root ] && \
          crit "$d 可被非 root 写入（owner=$(stat -c '%U' "$d" 2>/dev/null)）"
        SO_CNT=0
        while IFS= read -r so; do
          [ -z "$so" ] && continue
          SO_CNT=$((SO_CNT+1))
          [ "$SO_CNT" -gt 10 ] && { warn "  $d 内还有更多库文件未逐条列出"; break; }
          is_volatile_dir "$so" && crit "易失目录内存在可被链接的库: $so"
          if pkg_check_available && [ -z "$(pkg_owned "$so" "$(norm_alt "$so")")" ]; then
            warn "非包管理的库位于新增搜索路径内: $so"
          fi
        done < <(find "$d" -maxdepth 1 -name '*.so*' -type f 2>/dev/null)
      fi
    done < <(grep -vE '^[[:space:]]*(#|include)' "$f" 2>/dev/null)
  done
else
  info "无 /etc/ld.so.conf.d"
fi
[ "${#CONF_DIRS[@]}" -eq 0 ] && ok "搜索路径未额外扩展"

# ldconfig 实际解析结果：同名库被谁赢走
if command -v ldconfig >/dev/null; then
  DUP=$(ldconfig -p 2>/dev/null | awk '
    /=>/ {
      name=$1" "$2; path=$NF
      if (!(name in first)) { first[name]=path; cnt[name]=1 }
      else { cnt[name]++; rest[name]=rest[name]" "path }
    }
    END { for (n in cnt) if (cnt[n]>1) print n"|"first[n]"|"rest[n] }
  ')
  if [ -n "$DUP" ]; then
    while IFS='|' read -r name first rest; do
      if ! is_std "$first"; then
        crit "同名库解析优先级被改写: $name -> $first （哈希/真实副本: $rest ）"
      else
        info "同名库多份（优先级正常）: $name -> $first 其他:$rest"
      fi
    done <<< "$DUP"
  else
    ok "ldconfig 解析结果无同名库冲突"
  fi
fi

# ---------- 3. 环境变量持久化点 ----------
hdr "3. LD_* 环境变量的持久化位置"
ENVFILES=(/etc/environment /etc/profile /etc/bash.bashrc /etc/zsh/zshenv /etc/zsh/zprofile
          /etc/security/pam_env.conf /etc/rc.local /etc/cron.d /etc/crontab)
for d in /etc/profile.d /etc/default /etc/systemd/system /run/systemd/system /etc/sysconfig; do
  [ -d "$d" ] && ENVFILES+=("$d")
done
ENV_HIT=0
for f in "${ENVFILES[@]}"; do
  [ -e "$f" ] || continue
  hits=$(grep -rIn -E '(^|[^A-Za-z_])(export[[:space:]]+)?LD_(PRELOAD|LIBRARY_PATH|AUDIT|AOUT_PRELOAD|ELF_PRELOAD)[[:space:]]*=' "$f" 2>/dev/null)
  while IFS= read -r h; do
    [ -z "$h" ] && continue
    ENV_HIT=1
    file="${h%%:*}"
    case "$h" in
      *LD_PRELOAD*) crit "LD_PRELOAD 持久化: $h" ;;
      *) warn "LD_* 持久化: $h" ;;
    esac
    if pkg_check_available; then
      [ -z "$(pkg_owned "$file")" ] && crit "  该文件 $file 不属于任何发行版包"
    fi
    stat -c '  文件属性: %U:%G %a mtime %y' "$file" 2>/dev/null | cut -d. -f1
  done <<< "$hits"
done
for u in $(awk -F: '$6!="" && $6!="/" {print $6}' /etc/passwd 2>/dev/null); do
  for rc in .bashrc .bash_profile .profile .zshrc .zshenv; do
    [ -f "$u/$rc" ] || continue
    h=$(grep -Hn -E 'LD_(PRELOAD|LIBRARY_PATH)[[:space:]]*=' "$u/$rc" 2>/dev/null)
    [ -n "$h" ] && { crit "用户级持久化: $h"; ENV_HIT=1; }
  done
done
[ "$ENV_HIT" -eq 0 ] && ok "未发现 LD_PRELOAD/LD_LIBRARY_PATH 持久化配置"

# ---------- 4. systemd 单元 ----------
hdr "4. systemd 单元中的环境注入"
if command -v systemctl >/dev/null && [ -d /run/systemd/system ]; then
  SYSD=$(grep -rIl -E '^\s*(Environment|EnvironmentFile|PassEnvironment)\s*=' /etc/systemd /run/systemd 2>/dev/null | head -50)
  SYSHIT=0
  for f in $SYSD; do
    h=$(grep -Hn -E 'LD_(PRELOAD|LIBRARY_PATH)' "$f" 2>/dev/null)
    [ -n "$h" ] && { crit "systemd 单元注入: $h"; SYSHIT=1; }
  done
  [ "$SYSHIT" -eq 0 ] && ok "单元文件中无 LD_* 注入"
else
  info "非 systemd 运行环境，跳过"
fi

# ---------- 5. 运行时内存映射盘点 ----------
hdr "5. 运行时盘点：/proc/<pid>/maps 与 environ"
SUSP_SET=""
DELETED_SET=""
if [ -r /proc/1/maps ]; then
  AWKOUT=$(awk '
    /\.so/ {
      path=$NF
      if (path=="(deleted)") path=$(NF-1)
      if (path !~ /^\//) next
      print path "\t" FILENAME
    }
  ' /proc/[0-9]*/maps 2>/dev/null)
else
  AWKOUT=""
fi
PROC_COUNT=$(ls -d /proc/[0-9]* 2>/dev/null | wc -l)
info "扫描进程数: $PROC_COUNT"
ALL_LIBS=$(printf '%s\n' "$AWKOUT" | cut -f1 | sort -u | grep . )
NONSTD=$(printf '%s\n' "$ALL_LIBS" | grep -vE "$STD_PREFIX_RE" | grep . )
VOL=$(printf '%s\n' "$ALL_LIBS" | grep -E '^(/tmp|/var/tmp|/dev/shm)/' )
if [ -n "$VOL" ]; then
  while IFS= read -r l; do crit "易失目录中的库被加载进进程: $l"; done <<< "$VOL"
fi
# /run /home /root 等由下面的 NONSTD 告警项覆盖（多为用户自装工具）
if [ -n "$NONSTD" ]; then
  while IFS= read -r l; do
    owners=$(printf '%s\n' "$AWKOUT" | awk -F'\t' -v p="$l" '$1==p{print $2}' | sed 's|/proc/||;s|/maps||' | sort -u | paste -sd, -)
    warn "非标准路径的库已加载: $l  (pid: $owners)"
  done <<< "$NONSTD"
else
  ok "所有已加载 .so 均在标准目录下"
fi
[ -z "$NONSTD" ] && info "已加载唯一库数量: $(printf '%s\n' "$ALL_LIBS" | grep -c .)"

# 标准目录内但"不属于任何包"的库（批量查询，避免逐个起进程）
if pkg_check_available; then
  mapfile -t STDLIBS < <(printf '%s\n' "$ALL_LIBS" | grep -E "$STD_PREFIX_RE" | grep .)
  if [ "${#STDLIBS[@]}" -gt 0 ]; then
    CAND=()
    for l in "${STDLIBS[@]}"; do CAND+=("$l" "$(norm_alt "$l")"); done
    case "$PKG" in
      dpkg)   OWNED=$(dpkg-query -S "${CAND[@]}" 2>/dev/null | awk -F': ' '{print $NF}' | sort -u) ;;
      rpm)    OWNED=$(rpm -qf "${CAND[@]}" 2>/dev/null | grep -v 'not owned' | sort -u) ;;
      pacman) OWNED=$(for p in "${CAND[@]}"; do pacman -Qo "$p" >/dev/null 2>&1 && echo "$p"; done | sort -u) ;;
    esac
    UNOWNED=0
    for l in "${STDLIBS[@]}"; do
      if printf '%s\n' "$OWNED" | grep -qxF "$l" || printf '%s\n' "$OWNED" | grep -qxF "$(norm_alt "$l")"; then continue; fi
      UNOWNED=$((UNOWNED+1))
      [ "$UNOWNED" -gt 15 ] && { warn "  （还有更多未列出）"; break; }
      warn "已加载但不属于任何发行版包（第三方/投放物需人工确认）: $l"
    done
    [ "$UNOWNED" -eq 0 ] && ok "标准目录下已加载的库全部由包管理器负责"
  fi
fi

# environ 层面的运行时注入
ENVPIDS=0
for d in /proc/[0-9]*; do
  [ -r "$d/environ" ] || continue
  e=$( { tr '\0' '\n' < "$d/environ"; } 2>/dev/null | grep -E '^LD_(PRELOAD|LIBRARY_PATH)=' )
  [ -z "$e" ] && continue
  ENVPIDS=$((ENVPIDS+1))
  pid=${d#/proc/}
  cmd=$( { tr '\0' ' ' < "$d/cmdline"; } 2>/dev/null | cut -c1-60)
  warn "运行中进程带着 LD_*: pid=$pid ($cmd) -> $(printf '%s' "$e" | paste -sd';' -)"
done
[ "$ENVPIDS" -eq 0 ] && ok "没有存活进程带 LD_PRELOAD/LD_LIBRARY_PATH"

# 映射中存在已删除文件（加载后被删）
DEL_PATHS=$(grep -h '(deleted)' /proc/[0-9]*/maps 2>/dev/null | grep '\.so' | awk '{print $(NF-1)}' | sort -u)
if [ -n "$DEL_PATHS" ]; then
  while IFS= read -r p; do [ -n "$p" ] && warn "库文件在加载后被删除（痕迹清理）: $p"; done <<< "$DEL_PATHS"
else
  ok "无\"加载后即删除\"的库映射"
fi

# ---------- 6. 已知特征名与高危位置 ----------
hdr "6. 已知 rootkit 库名特征 / 高危目录中的库文件"
KNOWN_RE='(libshow\.so|libproc\.a|ld-linuxv\.so|libprocesshider\.so|libhide\.so|libbeast\.so)'
KH=$(find / -xdev -regextype posix-extended -regex ".*/$KNOWN_RE" 2>/dev/null | head -20)
[ -n "$KH" ] && while IFS= read -r f; do crit "命中已知 rootkit 库文件名: $f"; done <<< "$KH"
[ -z "$KH" ] && ok "未命中已知 rootkit 库文件名特征"
VOLF=$(find /tmp /var/tmp /dev/shm -xdev -name '*.so*' -type f 2>/dev/null)
VOLHIT=0
if [ -n "$VOLF" ]; then
  while IFS= read -r f; do
    is_elf "$f" || continue
    VOLHIT=$((VOLHIT+1)); [ "$VOLHIT" -gt 10 ] && { crit "  （/tmp|/var/tmp|/dev/shm 内还有更多，已截断）"; break; }
    crit "易失目录中存在共享库文件: $f ($(stat -c '%s bytes %U:%G %a' "$f"))"
  done <<< "$VOLF"
fi
[ "$VOLHIT" -eq 0 ] && ok "/tmp、/var/tmp、/dev/shm 内无共享库文件"
# 用户目录 / run / var 下的库多为自装工具（pip venv、手动编译），降为告警并限量
# 语言生态的扩展模块（site-packages / venv / node_modules）不是链接期劫持目标，单独折叠计数
USERF=$(find /home /root /run /var/lib -xdev -name '*.so*' -type f 2>/dev/null | head -60)
UHIT=0; FOLD=0
if [ -n "$USERF" ]; then
  while IFS= read -r f; do
    is_elf "$f" || continue
    case "$f" in
      */site-packages/*|*/dist-packages/*|*/venvs/*|*/.local/lib/python*/*|*/node_modules/*|*/gems/*)
        FOLD=$((FOLD+1)); continue ;;
    esac
    UHIT=$((UHIT+1)); [ "$UHIT" -gt 5 ] && { warn "  （用户目录下还有更多共享库，已截断）"; break; }
    warn "用户/运行时目录下的共享库（多为自装工具，需人工确认）: $f"
  done <<< "$USERF"
fi
[ "$UHIT" -eq 0 ] && ok "/home、/root、/run、/var/lib 内无共享库文件"
[ "$FOLD" -gt 0 ] && info "另跳过 $FOLD 个语言包扩展模块（site-packages/venv/node_modules 等，非链接期劫持面）"

# ---------- 7. 反隐藏交叉验证 ----------
hdr "7. 反隐藏交叉验证（对抗 hook open/stat 的恶意库）"
if [ -s /etc/ld.so.preload ]; then
  SHELLREAD=$( { cat /etc/ld.so.preload; } 2>/dev/null | md5sum | cut -d' ' -f1 )
  PROC1READ=$( { cat /proc/1/root/etc/ld.so.preload; } 2>/dev/null | md5sum | cut -d' ' -f1 )
  if [ "$SHELLREAD" = "$PROC1READ" ]; then
    info "两个不同路径读取一致（$SHELLREAD）——路径级隐藏 hook 未生效，或对两个路径都生效"
  else
    crit "两路径读取不一致（/etc=$SHELLREAD /proc/1/root/etc=$PROC1READ）——存在路径级隐藏 hook"
  fi
  BB=$(command -v busybox || true)
  if [ -n "$BB" ] && is_static_bin "$BB"; then
    BBREAD=$("$BB" cat /etc/ld.so.preload 2>/dev/null | md5sum | cut -d' ' -f1)
    if [ "$BBREAD" = "$SHELLREAD" ]; then
      info "静态读取器（$BB）结果一致，读数可信"
    else
      crit "静态读取器与 shell 读数不一致：shell=$SHELLREAD 静态=$BBREAD"
      info "静态读取器看到的真实内容："
      "$BB" cat /etc/ld.so.preload 2>/dev/null | sed 's/^/        /'
    fi
  elif [ -n "$BB" ]; then
    warn "本机 busybox 是动态链接（同样会被 preload 库污染），不能当可信读取器；请装 busybox-static"
  else
    warn "本机无静态读取器（busybox-static），无法交叉验证读数；被 hook 时本脚本的结论不成立"
  fi
  info "内核视角佐证：/proc/1/maps 中 .so 数量 = $(grep -c '\.so' /proc/1/maps 2>/dev/null)"
else
  ok "无 /etc/ld.so.preload，交叉验证无对象"
fi

# ---------- 9. 深度：标准目录全量包归属 ----------
# 补一个前面所有动态检查都盖不到的盲区：库已落盘、但当前没人加载它（例如已投放还没触发）
if [ "$DEEP" = 1 ] && [ -n "$PKG" ]; then
  hdr "9. 深度检查：标准目录下所有 .so 的包归属（--no-deep 可跳过）"
  TMPD=$(mktemp -d 2>/dev/null || echo /tmp)
  norm_stream() { sed -e 's|^/lib/|/usr/lib/|' -e 's|^/lib64/|/usr/lib64/|' | sort -u; }
  case "$PKG" in
    dpkg)   dpkg-query -L $(dpkg-query -f '${binary:Package}\n' -W 2>/dev/null) 2>/dev/null | norm_stream > "$TMPD/owned" ;;
    rpm)    rpm -qa --qf '[%{FILENAMES}\n]' 2>/dev/null | norm_stream > "$TMPD/owned" ;;
    pacman) pacman -Qlq 2>/dev/null | norm_stream > "$TMPD/owned" ;;
  esac
  find /lib /usr/lib /lib64 /usr/lib64 -xdev \
       \( -name '*.so' -o -name '*.so.*' \) -type f 2>/dev/null | norm_stream > "$TMPD/present"
  if [ ! -s "$TMPD/owned" ]; then
    info "无法取得包文件清单，跳过深度检查"
  else
    TOTAL=$(wc -l < "$TMPD/present")
    UNOWNED=$(comm -13 "$TMPD/owned" "$TMPD/present" 2>/dev/null)
    UNN=$(printf '%s\n' "$UNOWNED" | grep -c . || true)
    info "标准目录下共 $TOTAL 个共享库，其中不属于任何发行版包的有 $UNN 个"
    printf '%s\n' "$UNOWNED" | grep . | while IFS= read -r f; do
      printf '      %s  [%s %s]\n' "$f" "$(stat -c '%U:%G %a' "$f" 2>/dev/null)" \
        "$(stat -c '%y' "$f" 2>/dev/null | cut -d. -f1)"
    done | head -20
    if [ "$UNN" -gt 0 ]; then
      warn "上列库不属于发行版包：第三方驱动（nvidia/docker/virtualbox）、源码编译安装、或投放物都在此列，需逐个确认"
    else
      ok "标准目录下所有共享库均由包管理器负责"
    fi
  fi
  rm -rf "$TMPD"
fi

# ---------- 基线 ----------
hdr "8. 基线"
# 基线只收录"与包管理器无关"的映射库：全量映射库集合随运行进程波动，放进去只会产生噪声
SNAP=$( { printf '# ld.so.preload\n'; cat /etc/ld.so.preload 2>/dev/null
          printf '# conf\n'; cat /etc/ld.so.conf.d/*.conf 2>/dev/null | grep -v '^#'
          printf '# mapped-nonstandard\n'; printf '%s\n' "$ALL_LIBS" | grep -vE "$STD_PREFIX_RE" | grep .; } | sort -u )
if [ "$MODE" = save ]; then
  install -d "$(dirname "$BASE")" 2>/dev/null
  printf '%s\n' "$SNAP" > "$BASE" && ok "基线已保存: $BASE ($(printf '%s\n' "$SNAP" | wc -l) 行)"
  exit 0
elif [ "$MODE" = diff ]; then
  if [ ! -f "$BASE" ]; then crit "基线不存在: $BASE（先跑 --save-baseline）"; else
    NEW=$(comm -13 <(sort -u "$BASE") <(printf '%s\n' "$SNAP" | sort -u))
    printf '%s\n' "$NEW" | grep -v '^$' | grep -v '^#' | while IFS= read -r l; do
      [[ "$l" =~ \.so ]] && crit "基线外新增已加载库: $l" || warn "基线外新增配置: $l"
    done
    [ -z "$(printf '%s\n' "$NEW" | grep -v '^$' | grep -v '^#')" ] && ok "与基线一致，无新增"
  fi
  [ "$CRIT" -gt 0 ] && exit 2; [ "$WARN" -gt 0 ] && exit 1; exit 0
fi

# ---------- 结论 ----------
hdr "结论"
printf '严重: %d  告警: %d\n' "$CRIT" "$WARN"
if [ "$CRIT" -gt 0 ]; then
  printf '%s发现严重动态库劫持迹象，按上面顺序逐条核验；先在干净环境（静态 busybox / 只读介质 / 离线分析）复核读数。%s\n' "$c_red" "$c_off"
  exit 2
elif [ "$WARN" -gt 0 ]; then
  printf '存在需人工确认的项，未见确定性劫持。\n'; exit 1
else
  printf '未发现动态库劫持迹象（注意：无法覆盖"基线之前就已植入"的情况，请启用 --save-baseline）。\n'; exit 0
fi
