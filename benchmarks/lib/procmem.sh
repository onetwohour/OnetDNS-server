#!/bin/sh
# 엔진 하나가 실제로 차지하는 물리 메모리를 측정한다. `. "$SRC/../lib/procmem.sh"`로 읽어 쓴다.
#
# **단일 PID의 VmRSS를 읽으면 안 된다.** NSD는 server-count만큼 자식을 fork하므로
# 하네스가 붙잡은 PID(부모)는 존 데이터를 거의 가지고 있지 않다 — 80만 레코드 존에서
# 부모가 11 MiB, 트리 전체는 88 MiB였다. 반대로 자식 VmRSS를 그냥 더하면 fork로
# 공유된 페이지를 여러 번 세어 과대 계상한다. 두 오차가 없는 값은 Pss뿐이므로
# 프로세스 트리 전체의 Pss를 더한다.
#
# 트리는 부모/자식 관계가 아니라 **명령줄에 그 엔진의 설정 경로가 들어 있는지**로
# 찾는다. 엔진이 데몬화하며 부모를 바꿔도(setsid) 놓치지 않기 위해서다.
#
# 어느 값을 인용할지는 프로세스 수가 정한다.
#  - procs == 1: **VmRSS**를 쓴다. 엔진 안에서 공유되는 페이지가 없으므로 이중 계상이
#    없고, 이 값이 그 엔진이 혼자 돌 때 실제로 만지는 페이지다.
#  - procs > 1: **Pss**를 쓴다. VmRSS 합은 fork 공유분을 여러 번 세고, PID 하나는
#    자식 몫을 전부 놓친다.
#
# Pss는 라이브러리 페이지를 다른 프로세스와 나눠 계상하므로 **동적 링크 엔진에 유리하고
# 정적 musl 빌드에 불리하다**(OnetDNS 빌드는 공유할 상대가 없어 Pss ≈ VmRSS다). 즉 Pss로
# 낸 교차 엔진 비교는 OnetDNS에 보수적인 방향이다 — 그 방향이면 과장이 아니므로 그대로
# 인용해도 되지만, 반대 방향의 주장에는 쓰지 말 것.

# 이 명령줄 조각을 가진 프로세스 번호들. 셸은 뺀다 — 하네스 자신의 명령줄에도
# 같은 경로가 들어 있어 그대로 두면 자기 자신을 센다.
engine_pids() { # needle
  needle=$1
  found=""
  for entry in /proc/[0-9]*; do
    pid=${entry#/proc/}
    [ "$pid" = "$$" ] && continue
    # 훑는 도중에 프로세스가 사라질 수 있다. 리다이렉션 실패 메시지는 tr이 아니라
    # 셸이 내므로 중괄호로 묶어 전부 버려야 한다.
    line=$( { tr '\0' ' ' <"$entry/cmdline"; } 2>/dev/null ) || continue
    [ -n "$line" ] || continue
    case "$line" in
      *"$needle"*) ;;
      *) continue ;;
    esac
    case "$line" in
      sh\ *|bash\ *|dash\ *|/bin/sh\ *|/bin/bash\ *) continue ;;
    esac
    found="$found $pid"
  done
  printf '%s' "$found"
}

# "프로세스 수 Pss합KiB VmRSS합KiB". smaps_rollup이 없는 커널에서는 Pss 곳에
# VmRSS 합을 넣는다(그 커널에서는 fork하는 엔진을 정확히 측정할 수 없다).
engine_memory() { # needle
  engine_pids "$1" | awk -v procdir=/proc '
    {
      for (i = 1; i <= NF; i++) {
        pid = $i
        rss = 0
        while ((getline line < (procdir "/" pid "/status")) > 0)
          if (line ~ /^VmRSS:/) { split(line, f, /[ \t]+/); rss = f[2] }
        close(procdir "/" pid "/status")
        pss = 0
        seen = 0
        while ((getline line < (procdir "/" pid "/smaps_rollup")) > 0)
          if (line ~ /^Pss:/) { split(line, f, /[ \t]+/); pss = f[2]; seen = 1 }
        close(procdir "/" pid "/smaps_rollup")
        if (!seen) pss = rss
        rss_sum += rss
        pss_sum += pss
        n++
      }
    }
    END { printf "%d %d %d", n + 0, pss_sum + 0, rss_sum + 0 }
  '
}

# 트리 Pss만. 못 측정하면 0.
engine_pss_kib() { # needle
  engine_memory "$1" | awk '{ print $2 }'
}
