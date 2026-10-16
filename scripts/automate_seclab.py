import subprocess
import time
import psutil
from pywinauto import Application

exe_path = r"I:\1_taiLieuDaiHoc\ATPM\TAI_LIEU_VA_YEU_CAU\04_Cong_Cu_Giang_Vien\SecLabFramework.exe"
print(f"[*] Starting {exe_path}...")
proc = subprocess.Popen([exe_path])

try:
    print("[*] Waiting for process initialization...")
    time.sleep(7)
    p = psutil.Process(proc.pid)
    children = p.children(recursive=True)
    if not children:
        print("[-] No child process found!")
        exit(1)
    
    child = children[0]
    print(f"[+] Child process PID: {child.pid}")
    
    app = Application(backend="win32").connect(process=child.pid)
    windows = app.windows()
    print(f"[+] Found {len(windows)} windows:")
    target_win = None
    for w in windows:
        print(f"    - Handle: {w.handle}, Title: {repr(w.window_text())}, Class: {w.class_name()}, Rect: {w.rectangle()}")
        if w.rectangle().width() > 300:
            target_win = w
            
    if target_win:
        print(f"[+] Target window selected: Title={target_win.window_text()}, Class={target_win.class_name()}")
        img = target_win.capture_as_image()
        out_img = r"I:\1_taiLieuDaiHoc\ATPM\Nhom11_BTL_ChuDe4_Fuzzing\results\screenshots\seclab_live_launch.png"
        img.save(out_img)
        print(f"[+] Saved screenshot to: {out_img}")
        
except Exception as e:
    print(f"[-] Exception: {e}")
    import traceback
    traceback.print_exc()
finally:
    print("[*] Terminating processes...")
    try:
        p = psutil.Process(proc.pid)
        for c in p.children(recursive=True):
            c.terminate()
        p.terminate()
    except Exception:
        pass
