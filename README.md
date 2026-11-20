# Network Sentinel

We built Network Sentinel for Data-Driven Cybersecurity at the University of Cincinnati. We started with a packet-counting threshold and later added a random forest. The Streamlit dashboard lets you replay a saved run or inspect IPv4 traffic on a local interface.

**Pardha Saradhi Edupalli and Lakshmi Aishwarya Undi**

## What the dashboard shows

Our saved run contains **54,953 packets**. The detector labeled **43,136** normal, **11,635** TCP SYN flood and **182** UDP flood. We don’t have independent labels for those packets, so we can report what the detector flagged but can’t estimate its false-positive rate from this run.

The charts use full-run totals. The table includes an equal-sized sample of each recorded label, so it can be used to inspect examples. It contains protocol, byte length, the cumulative per-source count and the recorded label.

## Run the replay

Run these commands in PowerShell from this project folder with Python 3.12 installed.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\python -m streamlit run app.py
```

Select **Saved course run**. For a terminal-only check, run `.\.venv\Scripts\python detector.py` after installing the requirements.

## How the model works

We trained a 100-tree random forest on hour, minute, second and protocol. The 5,180 training records contain three flood labels and no examples of normal traffic. Each protocol is paired with a single label, which limits what the model can learn about the difference between a flood and ordinary traffic.

`detector.py` rebuilds the model from a CSV of repeated observations. During capture, packet size and the cumulative count for each source also feed a set of rules. The saved replay displays the labels recorded at capture time. It does not recompute them with the rebuilt model.

## Optional local capture

Install `requirements-capture.txt` in the same environment. Windows live capture also requires a working Npcap installation and permission to read the local interface. Select **Local passive capture** and then **Capture metadata**. The app collects at most 200 packets over five seconds. Source addresses are used in memory to count events and are omitted from displayed rows. The course midterm was a rule-based passive monitor, which preceded the final model.

The earlier `midterm_baseline.py` shows the count-based monitor we started with. It prints threshold crossings while keeping source addresses out of the output.
