# Heavily, heavily based on this example:
# http://gnuplot-tricks.blogspot.com/2010/06/broken-axis-once-more.html

load "gnuplot-palettes/inferno.pal"

# set xlabel "Rule Count"
set ylabel "Round-trip Time (\\si{\\micro\\second})" offset 0,4,0

#set yrange [0:130]

unset key
bm = 0.15
lm = 0.12
rm = 0.95
gap = 0.03
size = 0.75
y1 = 14.0; y2 = 31.0; y3 = 270.0; y4 = 420.0

topratio = 0.45
botratio = 1.0 - topratio

set multiplot
set xtics nomirror
set ytics nomirror
set lmargin at screen lm
set rmargin at screen rm
set bmargin at screen bm
set tmargin at screen bm + size * botratio #(abs(y2-y1) / (abs(y2-y1) + abs(y4-y3) ) )

set style boxplot nooutliers pointtype 7
set style data boxplot

set boxwidth 0.5
unset key
set pointsize 0.1

set key textcolor rgb "black"
set tics textcolor rgb "black"
set label textcolor rgb "black"

set key samplen 2 spacing 1 width -3

array Names[5]
Names[1] = "dpdk"
Names[2] = "xdphook"
Names[3] = "dpdk-xdp-pmd-custom"
Names[4] = "dpdk-afp-pmd"

array PNames[5]
PNames[1] = "DPDK"
PNames[2] = "Native XDP"
PNames[3] = "\\texttt{AF\\_XDP}"
PNames[4] = "\\texttt{AF\\_PACKET}"

array LineStyles[5]
LineStyles[1] = 1
LineStyles[2] = 2
LineStyles[3] = 4
LineStyles[4] = 6
LineStyles[5] = 7

file(n) = sprintf("../pktgen-results/l-%s-64B-0.dat", Names[n+1])
x_coord(n) = 1 + 2*n

set xtics () # clear all tics
set xtics nomirror
set grid noxtics
set for [i=0:3] xtics add (PNames[i + 1] x_coord(i))

set xrange [0.0:8.0]
set yrange [y1:y2]

set key above

plot for [i=0:2] file(i) u (x_coord(i)):($1/1.2e3):(1.0) every ::1 notitle ls LineStyles[i + 2]

unset xtics
unset xlabel
set border 2
set bmargin at screen bm + size * botratio + gap #(abs(y2-y1) / (abs(y2-y1) + abs(y4-y3) ) ) + gap
set tmargin at screen bm + size + gap
set yrange [y3:y4]

# set arrow from screen lm - gap / 4.0, bm + size * (abs(y2-y1) / (abs(y2-y1)+abs(y4-y3) ) ) - gap / 4.0 to screen \
lm + gap / 4.0, bm + size * (abs(y2-y1) / (abs(y2-y1) + abs(y4-y3) ) ) + gap / 4.0 nohead lc rgb '#a0a0a0'

# set arrow from screen lm - gap / 4.0, bm + size * (abs(y2-y1) / (abs(y2-y1)+abs(y4-y3) ) ) - gap / 4.0  + gap to screen \
lm + gap / 4.0, bm + size * (abs(y2-y1) / (abs(y2-y1) + abs(y4-y3) ) ) + gap / 4.0 + gap nohead lc rgb '#a0a0a0'

set arrow from screen lm - gap / 4.0, bm + size * botratio - gap / 4.0 to screen \
lm + gap / 4.0, bm + size * botratio + gap / 4.0 nohead lc rgb '#a0a0a0'

set arrow from screen lm - gap / 4.0, bm + size * botratio - gap / 4.0  + gap to screen \
lm + gap / 4.0, bm + size * botratio + gap / 4.0 + gap nohead lc rgb '#a0a0a0'

unset ylabel

plot for [i=3:3] file(i) u (x_coord(i)):($1/1.2e3):(1.0) every ::1 notitle ls LineStyles[i + 2]

unset multiplot