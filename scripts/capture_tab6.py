import ctypes
from ctypes import wintypes
import subprocess
import time
import psutil
from PIL import Image

exe_path = r"I:\1_taiLieuDaiHoc\ATPM\TAI_LIEU_VA_YEU_CAU\04_Cong_Cu_Giang_Vien\SecLabFramework.exe"
print(f"[*] Starting {exe_path}...")
proc = subprocess.Popen([exe_path])

try:
    time.sleep(7)
    p = psutil.Process(proc.pid)
    child = p.children(recursive=True)[0]
    
    user32 = ctypes.windll.user32
    gdi32 = ctypes.windll.gdi32
    
    target_hwnd = None
    def enum_cb(hwnd, lparam):
        length = user32.GetWindowTextLengthW(hwnd)
        if length > 0:
            buff = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buff, length + 1)
            if "Educational Security Suite" in buff.value:
                global target_hwnd
                target_hwnd = hwnd
                return False
        return True
    
    WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)
    user32.EnumWindows(WNDENUMPROC(enum_cb), 0)
    
    print(f"[+] Found target HWND: {target_hwnd}")
    if not target_hwnd:
        exit(1)
        
    rect = wintypes.RECT()
    user32.GetWindowRect(target_hwnd, ctypes.byref(rect))
    w = rect.right - rect.left
    h = rect.bottom - rect.top
    print(f"[+] Window Rect: {rect.left}, {rect.top}, {rect.right}, {rect.bottom} (Size: {w}x{h})")
    
    pt = wintypes.POINT(0, 0)
    user32.ClientToScreen(target_hwnd, ctypes.byref(pt))
    print(f"[+] Client screen pos: {pt.x}, {pt.y}")
    
    user32.ShowWindow(target_hwnd, 1) # SW_SHOWNORMAL
    user32.SetForegroundWindow(target_hwnd)
    time.sleep(0.5)
    
    # Calculate coordinate of Tab 6
    # Relative to client: x ≈ 780, y ≈ 15
    target_x = pt.x + 780
    target_y = pt.y + 15
    print(f"[*] Clicking Tab 6 at ({target_x}, {target_y})...")
    
    user32.SetCursorPos(target_x, target_y)
    time.sleep(0.2)
    MOUSEEVENTF_LEFTDOWN = 0x0002
    MOUSEEVENTF_LEFTUP = 0x0004
    user32.mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0)
    time.sleep(0.1)
    user32.mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0)
    time.sleep(2.0)
    
    # Re-fetch window rect
    user32.GetWindowRect(target_hwnd, ctypes.byref(rect))
    w = rect.right - rect.left
    h = rect.bottom - rect.top
    print(f"[+] Re-fetched Size: {w}x{h}")
    
    hdc_window = user32.GetWindowDC(target_hwnd)
    hdc_mem = gdi32.CreateCompatibleDC(hdc_window)
    hbm = gdi32.CreateCompatibleBitmap(hdc_window, w, h)
    gdi32.SelectObject(hdc_mem, hbm)
    ret = user32.PrintWindow(target_hwnd, hdc_mem, 2)
    print(f"[+] PrintWindow return: {ret}")
    
    class BITMAPINFOHEADER(ctypes.Structure):
        _fields_ = [
            ("biSize", wintypes.DWORD),
            ("biWidth", wintypes.LONG),
            ("biHeight", wintypes.LONG),
            ("biPlanes", wintypes.WORD),
            ("biBitCount", wintypes.WORD),
            ("biCompression", wintypes.DWORD),
            ("biSizeImage", wintypes.DWORD),
            ("biXPelsPerMeter", wintypes.LONG),
            ("biYPelsPerMeter", wintypes.LONG),
            ("biClrUsed", wintypes.DWORD),
            ("biClrImportant", wintypes.DWORD)
        ]
        
    bmi = BITMAPINFOHEADER()
    bmi.biSize = ctypes.sizeof(BITMAPINFOHEADER)
    bmi.biWidth = w
    bmi.biHeight = -h
    bmi.biPlanes = 1
    bmi.biBitCount = 32
    bmi.biCompression = 0
    
    buf = ctypes.create_string_buffer(w * h * 4)
    gdi32.GetDIBits(hdc_mem, hbm, 0, h, buf, ctypes.byref(bmi), 0)
    
    img = Image.frombuffer("RGBA", (w, h), buf, "raw", "BGRA", 0, 1)
    out_path = r"I:\1_taiLieuDaiHoc\ATPM\Nhom11_BTL_ChuDe4_Fuzzing\results\screenshots\seclab_real_tab6.png"
    img.save(out_path)
    print(f"[+] Saved image to: {out_path}")

finally:
    print("[*] Terminating process...")
    try:
        p = psutil.Process(proc.pid)
        for c in p.children(recursive=True):
            c.terminate()
        p.terminate()
    except Exception:
        pass
