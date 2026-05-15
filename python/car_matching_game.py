#!/usr/bin/python3

# Game -> Match the car make with its model

import random
import select
import sys
import termios
import time
import tty

print('########################################')
print('#                                      #')
print('#                                      #')
print('#        WELCOME! LETS BEGIN           #')
print('#      MATCH THE CAR MAKE & MODEL      #')
print('#                                      #')
print('#                                      #')
print('########################################')
print('')

# source of truth — (make, model) pairs
car_pairs = [
    ("Genesis",      "G70"),
    ("Audi",         "RS3"),
    ("BMW",          "M3"),
    ("Cadillac",     "CT4-V"),
    ("Mercedes-AMG", "C63"),
    ("Acura",        "Type S"),
    ("Nissan",       "GT-R"),
    ("Toyota",       "GR Supra"),
    ("Subaru",       "WRX STI"),
    ("Honda",        "Civic Type R"),
    ("Dodge",        "Challenger Hellcat"),
    ("Chevrolet",    "Corvette"),
    ("Ford",         "Mustang Shelby GT500"),
    ("Alfa Romeo",   "Giulia Quadrifoglio"),
    ("Volkswagen",   "Golf R"),
]

SECONDS_PER_ATTEMPT = 30


class TimedOut(Exception):
    pass


def timed_input(prompt, total_seconds, start_time, line_prefix='', newline=True):
    """
    line_prefix: text already on this line to the left of our prompt (used when
                 Make and Model share a line — bar redraws must include it).
    newline:     whether to emit \n when Enter is pressed (False for Make so
                 Model can appear on the same line).
    """
    sys.stdout.write(prompt)
    sys.stdout.flush()

    chars        = []
    last_elapsed = int(time.monotonic() - start_time)
    fd           = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)

    try:
        tty.setcbreak(fd)
        while True:
            elapsed = int(time.monotonic() - start_time)
            if elapsed >= total_seconds:
                raise TimedOut()

            if elapsed > last_elapsed:
                last_elapsed = elapsed
                bar       = '█' * elapsed + '░' * (total_seconds - elapsed)
                typed     = ''.join(chars)
                full_line = line_prefix + prompt + typed
                sys.stdout.write(f'\033[1A\r\033[K  [{bar}]\n\r\033[K{full_line}')
                sys.stdout.flush()

            r, _, _ = select.select([sys.stdin], [], [], 0.1)
            if not r:
                continue

            ch = sys.stdin.read(1)
            if ch in ('\n', '\r'):
                if newline:
                    sys.stdout.write('\n')
                    sys.stdout.flush()
                return ''.join(chars)
            elif ch in ('\x7f', '\x08'):
                if chars:
                    chars.pop()
                    sys.stdout.write('\b \b')
                    sys.stdout.flush()
            elif ch.lower() == 'q':
                sys.stdout.write('q\n')
                sys.stdout.flush()
                return 'q'
            elif ch.isdigit():
                chars.append(ch)
                sys.stdout.write(ch)
                sys.stdout.flush()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


def ask_try_again():
    """Ask 'Try Again? (y/n)' in raw mode. Returns True for y, False for n/q."""
    sys.stdout.write("  Try Again? (y/n) : ")
    sys.stdout.flush()
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        while True:
            r, _, _ = select.select([sys.stdin], [], [])
            ch = sys.stdin.read(1).lower()
            if ch == 'y':
                sys.stdout.write('y\n')
                sys.stdout.flush()
                return True
            elif ch in ('n', 'q'):
                sys.stdout.write('n\n')
                sys.stdout.flush()
                return False
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


def wait_for_enter():
    """Wait for Enter to continue or q to quit. Returns True if user wants to quit."""
    sys.stdout.write("  Press Enter to continue...  ")
    sys.stdout.flush()
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        while True:
            r, _, _ = select.select([sys.stdin], [], [])
            ch = sys.stdin.read(1)
            if ch in ('\n', '\r'):
                sys.stdout.write('\n')
                sys.stdout.flush()
                return False
            elif ch.lower() in ('q', 'n'):
                sys.stdout.write('\n')
                sys.stdout.flush()
                return True
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


def print_summary(level_times):
    if not level_times:
        return
    print("\n  ── Level Times ──────────────────────────")
    for level_num, secs in level_times:
        mins, s = divmod(int(secs), 60)
        label = f"{mins}m {s:02d}s" if mins else f"{s}s"
        print(f"  Level {level_num} : {label}")
    print('')


def current_bar(start_time, total_seconds):
    elapsed = int(time.monotonic() - start_time)
    filled  = min(elapsed, total_seconds)
    return '█' * filled + '░' * (total_seconds - filled)


def display_board(pairs, makes_order, models_order, matched, make_nums, model_nums):
    n = len(pairs)
    print(f"\n  {'#':<5} {'MAKE':<25} {'#':<5} MODEL")
    print(f"  {'─'*5} {'─'*25} {'─'*5} {'─'*25}")
    for i in range(n):
        make_str  = '[ matched ]' if makes_order[i]  in matched else pairs[makes_order[i]][0]
        model_str = '[ matched ]' if models_order[i] in matched else pairs[models_order[i]][1]
        print(f"  {make_nums[i]:<5} {make_str:<25} {model_nums[i]:<5} {model_str}")
    print('')


def play_level(level_num, total_levels, pairs):
    n = len(pairs)
    makes_order  = list(range(n))
    random.shuffle(makes_order)

    # derangement: no matching pair may appear on the same row
    models_order = makes_order[:]
    while any(models_order[i] == makes_order[i] for i in range(n)):
        random.shuffle(models_order)
    matched = set()

    # random display numbers — neither side has to start at 0
    pool          = list(range(10))
    make_nums     = random.sample(pool, n)
    model_nums    = random.sample(pool, n)
    make_num_map  = {num: i for i, num in enumerate(make_nums)}
    model_num_map = {num: i for i, num in enumerate(model_nums)}

    print(f"\n{'='*42}")
    print(f"  LEVEL {level_num} of {total_levels}  —  Match {n} cars")
    print(f"  {SECONDS_PER_ATTEMPT} seconds total — timer does not reset")
    print(f"{'='*42}")

    start_time = time.monotonic()  # starts once per level, never resets

    while len(matched) < n:
        display_board(pairs, makes_order, models_order, matched, make_nums, model_nums)
        print(f"  Remaining: {n - len(matched)}  |  'q' to quit")
        print(f"  [{current_bar(start_time, SECONDS_PER_ATTEMPT)}]")

        try:
            raw1 = timed_input("  Make  # : ", SECONDS_PER_ATTEMPT, start_time, newline=False)
            if raw1.strip().lower() == 'q':
                return 'quit'

            separator    = "    |    "
            line_prefix  = f"  Make  # : {raw1}{separator}"
            sys.stdout.write(separator)
            sys.stdout.flush()

            raw2 = timed_input("  Model # : ", SECONDS_PER_ATTEMPT, start_time, line_prefix=line_prefix)
            if raw2.strip().lower() == 'q':
                return 'quit'

        except TimedOut:
            print("\n  Time's up! Level failed.\n")
            return 'timeout'

        print('')

        try:
            p1, p2 = int(raw1), int(raw2)
        except ValueError:
            print("  Numbers only.\n")
            continue

        if p1 not in make_num_map or p2 not in model_num_map:
            print(f"  Make: pick from {sorted(make_num_map)}  |  Model: pick from {sorted(model_num_map)}\n")
            continue

        make_idx  = makes_order[make_num_map[p1]]
        model_idx = models_order[model_num_map[p2]]
        make  = pairs[make_idx][0]
        model = pairs[model_idx][1]
        print(f"  You chose: {make} + {model}")

        if make_idx == model_idx:
            print(f"  Match! — {make} {model}\n")
            matched.add(make_idx)
        else:
            print("  Try again\n")

    print(f"  Level {level_num} complete!\n")
    return True


def player_choice():
    pool = car_pairs[:]
    random.shuffle(pool)
    levels      = [pool[i:i + 4] for i in range(0, len(pool), 4)]
    total       = len(levels)
    i           = 0
    level_times = []

    while i < total:
        level_start = time.monotonic()
        result      = play_level(i + 1, total, levels[i])

        if result == 'quit':
            print_summary(level_times)
            print("  Goodbye!")
            return

        if result == 'timeout':
            print_summary(level_times)
            if ask_try_again():
                continue  # replay same level, fresh timer
            print("  Goodbye!")
            return

        # level complete — record time
        level_times.append((i + 1, time.monotonic() - level_start))

        if i == total - 1:
            print_summary(level_times)
            print("  Congratulations! You completed all levels and won the game!")
            return

        if wait_for_enter():
            print_summary(level_times)
            print("  Goodbye!")
            return

        i += 1


player_choice()
