import os
import time


def tail_with_rotation(filename: str) -> None:
    current_inode = None
    f = None

    while True:
        if not os.path.exists(filename):
            time.sleep(1)
            continue

        stat = os.stat(filename)

        # Detect rotation (inode changed)
        if stat.st_ino != current_inode:
            if f:
                f.close()
            f = open(filename, "r")
            current_inode = stat.st_ino
            print(" Re-attached to fresh log file.")

        line = f.readline()
        if not line:
            time.sleep(0.1)
            continue

        # Replace with your processing logic
        print(line, end="")


if __name__ == "__main__":
    tail_with_rotation("packets.json")
