import time
import sys

class SpiderMascot:
    STATES = {
        "idle": [
            r" / \(oo)/ \ ",
            r"//\(-.-)/\\",
        ],
        "success": [
            r" /|\(OvO)/|\ ",
        ],
        "warning": [
            r" ///\(ʘᴥʘ)/\\\ ",
        ],
        "confused": [
            r" / \(?_?)/ \ ",
        ],
    }

    def __init__(self, state="idle"):
        self.state = state
        self._blink_frame = 0

    def render(self):
        if self.state == "idle":
            # Blink between two frames
            frame = self.STATES["idle"][self._blink_frame]
            self._blink_frame = 1 - self._blink_frame  # toggle 0 <-> 1
            return frame
        else:
            frames = self.STATES.get(self.state, self.STATES["idle"])
            return frames[0] if isinstance(frames, list) else frames

    def set_state(self, state):
        if state in self.STATES:
            self.state = state
        else:
            self.state = "confused"

    def animate(self, duration=3.0, state=None):
        """Display the current (or given) state for `duration` seconds."""
        if state:
            self.set_state(state)
        
        start = time.time()
        try:
            while time.time() - start < duration:
                sys.stdout.write("\r" + self.render())
                sys.stdout.flush()
                time.sleep(0.5)  # blink/update every half second
        except KeyboardInterrupt:
            pass
        finally:
            print()  # newline after animation

    def show(self, state=None, duration=3.0):
        """Convenience: set state and animate."""
        self.animate(duration=duration, state=state)


# Quick test
if __name__ == "__main__":
    spider = SpiderMascot()
    
    print("Idle (blinking)...")
    spider.animate(duration=4, state="idle")
    
    print("Success!")
    spider.show(state="success", duration=3)
    
    print("Uh oh...")
    spider.show(state="warning", duration=5)
    
    print("Huh?")
    spider.show(state="confused", duration=2)
