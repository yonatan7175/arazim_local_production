## ARAZIM LOCAL 

### GOALS: 
- #####  understand G2 network structure
- ##### find communication primitives
- ##### build a local webiste on G2

### git structure: 
- ##### ./wiki/drive contains a url to google drive with explenatiosns
- ##### ./poc contains folder of the communication primitives

### installation:
- ##### install python
```bash
git clone git@github.com:yonatannisemnew/arazim_local.git
cd arazim_local
sudo python3 install/install.py        # Linux
python install\install.py              # Windows (prompts for UAC elevation)
```
- ##### what will happen?
LINUX: the app is copied to /opt/Arazim_Local and `arazim_local` is symlinked into /usr/local/bin.
WINDOWS: the app is copied to %ProgramData%\ArazimLocal, a launcher .bat is added to your desktop,
and that launcher's folder is added to the system-wide PATH, so `arazim_local` also runs from any
terminal (open a new one for the PATH change to take effect).
a shell script will be added to your desktop. 
double click it to lunch our dashboard 
set the button to On when you want to browse on G2
ON LINUX: it is possible to close the terminal window and keep working with the dashboard
##### TO VISIT THE WEBSITE: search on chrome arazim.local
