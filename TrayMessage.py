from win32gui import *
from win32con import *
from time import sleep


class WindowsBalloonTip:
    def __init__(self):
        message_map = {
            WM_DESTROY: self.OnDestroy,
        }
        # Register the Window class.
        wc = WNDCLASS()
        self.hinst = wc.hInstance = GetModuleHandle(None)
        wc.lpszClassName = "PythonTaskbar"
        wc.lpfnWndProc = message_map  # could also specify a wndproc.
        self.classAtom = RegisterClass(wc)

    def ShowWindow(self, title, msg, time):
        # Create the Window.
        style = WS_OVERLAPPED | WS_SYSMENU
        self.hwnd = CreateWindow(self.classAtom, "Taskbar", style, \
                                 0, 0, CW_USEDEFAULT, CW_USEDEFAULT, \
                                 0, 0, self.hinst, None)
        UpdateWindow(self.hwnd)

        hicon = LoadIcon(0, IDI_APPLICATION)
        nid = (self.hwnd, 0, 0, WM_USER + 20, hicon, "tooltip")
        Shell_NotifyIcon(NIM_ADD, nid)
        Shell_NotifyIcon(NIM_MODIFY, \
                         (self.hwnd, 0, NIF_INFO, WM_USER + 20, \
                          hicon, "Balloon  tooltip", msg, 200, title))
        # self.show_balloon(title, msg)
        sleep(int(time))
        DestroyWindow(self.hwnd)

    def OnDestroy(self, hwnd, msg, wparam, lparam):
        nid = (self.hwnd, 0)
        Shell_NotifyIcon(NIM_DELETE, nid)
        PostQuitMessage(0)  # Terminate the app.