import os

# Force SDL's X11 video backend before pygame loads. In a Wayland session SDL
# would otherwise draw window decorations via libdecor -> GTK -> gdk-pixbuf ->
# glycin, whose out-of-process image loader blocks on session/D-Bus IPC that
# root can't reach - hanging pygame.display.set_mode() until it's interrupted
# (Ctrl+C). Since we run the dashboard as root, route through XWayland instead.
# `setdefault` lets a user still override it from the environment.
os.environ.setdefault("SDL_VIDEODRIVER", "x11")

import pygame
import sys
import subprocess
import signal
import platform
import dashboard_utils

PARENT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
MANAGER_PATH = os.path.join(PARENT_DIR, "manager", "manager.py")
sys.path.append(PARENT_DIR)

from utils import manager_utils, premissions_stats
from installers import uninstaller

if sys.platform != "win32":
    signal.signal(signal.SIGCHLD, signal.SIG_IGN)


class Config:
    SCREEN_SIZE = (750, 300)
    BG_COLOR = (30, 30, 30)
    GREEN = (0, 200, 0)
    RED = (200, 0, 0)
    YELLOW = (255, 200, 0)
    WHITE = (255, 255, 255)
    GRAY = (50, 50, 50)
    DARK_RED = (130, 0, 0)


# --- MODEL: The Business Logic ---
class AppManager:
    def __init__(self):
        self._autorun = False

    def get_status(self):
        try:
            running = manager_utils.is_manager_running()
            if not running:
                return "STOPPED"
            is_connected = manager_utils.load_is_connected()
            return "RUNNING" if is_connected else "SLEEPING"
        except:
            return "STOPPED"

    def open_manager(self):
        manager_dir = os.path.dirname(MANAGER_PATH)
        if sys.platform == "win32":
            kwargs = {"creationflags": subprocess.CREATE_NEW_CONSOLE}
        else:
            kwargs = {"start_new_session": True}
        subprocess.Popen([sys.executable, MANAGER_PATH], cwd=manager_dir, **kwargs)

    def close_manager(self):
        manager_utils.kill_manager()

    def uninstall_app(self):
        uninstaller.uninstall_project()


# --- VIEW: UI Components ---
class Button:
    def __init__(self, text, x, y, w=120, h=80, color=None):
        self.rect = pygame.Rect(x, y, w, h)
        self.text = text
        self.active = False
        self.base_color = color if color else Config.RED
        self.font = pygame.font.Font(None, 32)
        self.sub_font = pygame.font.Font(None, 22)

    def draw(self, screen):
        color = Config.GREEN if self.active else self.base_color
        status_text = "ON" if self.active else "OFF"

        pygame.draw.rect(screen, color, self.rect, border_radius=12)
        pygame.draw.rect(screen, Config.WHITE, self.rect, 2, border_radius=12)

        lbl_surf = self.font.render(self.text, True, Config.WHITE)
        screen.blit(lbl_surf, lbl_surf.get_rect(center=self.rect.center))

        stat_surf = self.sub_font.render(status_text, True, (200, 200, 200))
        screen.blit(
            stat_surf,
            stat_surf.get_rect(midtop=(self.rect.centerx, self.rect.bottom + 5)),
        )

    def is_clicked(self, pos):
        return self.rect.collidepoint(pos)

class UninstallButton(Button):
    def __init__(self, x, y):
        super().__init__("UNINSTALL", x, y, w=160, h=80, color=Config.DARK_RED)
        self.confirm_mode = False
        self.processing = False # New state

    def draw(self, screen):
        # Determine visual state
        if self.processing:
            display_color = Config.GRAY
            display_text = "REMOVING..."
        elif self.confirm_mode:
            display_color = Config.RED
            display_text = "CONFIRM?"
        else:
            display_color = self.base_color
            display_text = "UNINSTALL"

        pygame.draw.rect(screen, display_color, self.rect, border_radius=12)
        pygame.draw.rect(screen, Config.WHITE, self.rect, 2, border_radius=12)

        lbl_surf = self.font.render(display_text, True, Config.WHITE)
        screen.blit(lbl_surf, lbl_surf.get_rect(center=self.rect.center))

        if self.confirm_mode and not self.processing:
            hint_surf = self.sub_font.render("Click again to confirm", True, Config.YELLOW)
            screen.blit(hint_surf, hint_surf.get_rect(midtop=(self.rect.centerx, self.rect.bottom + 5)))

class StatusDisplay:
    def __init__(self, x, y, w=200, h=80):
        self.rect = pygame.Rect(x, y, w, h)
        self.font = pygame.font.Font(None, 48)
        self.lbl_font = pygame.font.Font(None, 24)

    def draw(self, screen, status_text):
        pygame.draw.rect(screen, Config.GRAY, self.rect, border_radius=8)
        pygame.draw.rect(screen, (100, 100, 100), self.rect, 2, border_radius=8)

        if status_text == "RUNNING":
            color = Config.GREEN
        elif status_text == "SLEEPING":
            color = Config.YELLOW
        else:
            color = (255, 80, 80)

        text_surf = self.font.render(status_text, True, color)
        screen.blit(text_surf, text_surf.get_rect(center=self.rect.center))

        lbl_surf = self.lbl_font.render("STATUS", True, (150, 150, 150))
        screen.blit(
            lbl_surf,
            lbl_surf.get_rect(midbottom=(self.rect.centerx, self.rect.top - 5)),
        )


# --- CONTROLLER: The Main App ---
class DashboardApp:
    def __init__(self):
        pygame.init()
        self.screen = pygame.display.set_mode(Config.SCREEN_SIZE)
        pygame.display.set_caption("Modular Dashboard")
        self.clock = pygame.time.Clock()
        self.running = True

        self.manager = AppManager()
        
        # UI Layout
        self.btn_power = Button("POWER", 40, 100)
        self.display = StatusDisplay(200, 100)
        # Placeholder space for Autorun at x=440
        self.btn_uninstall = UninstallButton(570, 100)

    def handle_input(self):
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                self.running = False

            if event.type == pygame.MOUSEBUTTONDOWN:
                if self.btn_power.is_clicked(event.pos):
                    if self.btn_power.active:
                        self.manager.close_manager()
                    else:
                        self.manager.open_manager()
                    self.btn_uninstall.confirm_mode = False

                elif self.btn_uninstall.is_clicked(event.pos):
                    if not self.btn_uninstall.confirm_mode:
                        self.btn_uninstall.confirm_mode = True
                    else:
                        # 1. Update State
                        self.btn_uninstall.processing = True
                        self.btn_uninstall.confirm_mode = False
                        
                        # 2. Force Redraw so the user sees "REMOVING..."
                        self.draw()
                        
                        # 3. Call the actual uninstall function
                        self.manager.uninstall_app()
                        
                        # 4. Finish (Optional: close app)
                        self.running = False 
                
                else:
                    self.btn_uninstall.confirm_mode = False
    def sync_state(self):
        status = self.manager.get_status()
        self.btn_power.active = (status != "STOPPED")

    def draw(self):
        self.screen.fill(Config.BG_COLOR)
        self.btn_power.draw(self.screen)
        self.display.draw(self.screen, self.manager.get_status())
        self.btn_uninstall.draw(self.screen)
        pygame.display.flip()

    def run(self):
        while self.running:
            self.handle_input()
            self.sync_state()
            self.draw()
            self.clock.tick(30)

        pygame.quit()
        sys.exit()


# --- ENTRY POINT ---
if __name__ == "__main__":
    try:
        premissions_stats.root_check()
    except AttributeError:
        pass # Handle if mock
        
    app = DashboardApp()
    app.run()