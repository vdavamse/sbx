# Startup latency, three runs of `ONLY=latency run.sh`

Recorded back to back after the full run, on a host with other load (see the bare `true` row).

## Run 1

```
date:     2026-11-08T15:39:57Z
sbx:      sbx 0.1.0 (8fefdff1d13d34d0…)
srt:      0.0.81
runner:   b51ad6a

startup latency, 20 runs of true, median (ms):
  bare true         median     1.1  min     1.0  max     1.9  (n=20)
  sbx run           median    33.2  min    20.2  max    52.9  (n=20)
  srt               median   530.9  min   332.1  max   855.8  (n=20)
  node -e 0         median    61.1  min    30.9  max   100.3  (n=20)
  srt --version     median   249.3  min   182.8  max   368.0  (n=20)
  srt, empty policy median   549.2  min   421.4  max   721.4  (n=20)
```

## Run 2

```
date:     2026-11-08T15:40:30Z
sbx:      sbx 0.1.0 (8fefdff1d13d34d0…)
srt:      0.0.81
runner:   b51ad6a

startup latency, 20 runs of true, median (ms):
  bare true         median     3.2  min     2.9  max     4.0  (n=20)
  sbx run           median    36.4  min    24.0  max    78.1  (n=20)
  srt               median   483.5  min   344.8  max   662.5  (n=20)
  node -e 0         median    49.8  min    23.5  max    91.2  (n=20)
  srt --version     median   265.8  min   179.7  max   409.5  (n=20)
  srt, empty policy median   547.4  min   336.3  max   668.4  (n=20)
```

## Run 3

```
date:     2026-11-08T15:41:03Z
sbx:      sbx 0.1.0 (8fefdff1d13d34d0…)
srt:      0.0.81
runner:   b51ad6a

startup latency, 20 runs of true, median (ms):
  bare true         median     0.8  min     0.7  max     1.0  (n=20)
  sbx run           median    15.5  min    13.8  max    16.9  (n=20)
  srt               median   478.8  min   316.4  max   714.6  (n=20)
  node -e 0         median    30.2  min    24.5  max    86.0  (n=20)
  srt --version     median   220.8  min   179.5  max   388.8  (n=20)
  srt, empty policy median   491.8  min   340.0  max   719.4  (n=20)
```
