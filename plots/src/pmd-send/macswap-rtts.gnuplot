load "gnuplot-palettes/inferno.pal"

# set xlabel "Rule Count"
set ylabel "Round-trip Time (\\si{\\micro\\second})"

#set yrange [0:130]

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
set for [i=0:2] xtics add (PNames[i + 1] x_coord(i))

set key above

plot for [i=0:2] file(i) u (x_coord(i)):($1/1.2e3):(1.0) every ::1 notitle ls LineStyles[i + 2]
