#!/usr/bin/python3

# Game -> Match the car with its model

print('########################################')
print('#                                      #')
print('#                                      #')
print('#        WELCOME! LETS BEGIN           #')
print('#      MATCH THE CAR MAKE & MODEL      #')
print('#                                      #')
print('#                                      #')
print('########################################')
print('')

# arrays of cars and models
arr_cars = ["Genesis", "Audi", "BMW", "Cadilac", "Mercedes-AMG", "Acura"]
arr_models = ["RS3", "G70", "M3", "C63", "Type S", "CT4-V"]
good_match = "You found a match!"
bad_match = "Try again"

def player_choice():
    match_counter = 0  # counter for matches found

    while True:
        try:
            print("Enter 2 numbers between 0 and 5 (or 9 to quit):")
            player_input1 = int(input("First Number: "))
            player_input2 = int(input("Second Number: "))
            print('')
        except ValueError:
            print("⚠️ Enter numbers only.\n")
            continue

        # exit game manually
        if player_input1 == 9: #or player_input2 == 9:
            print("Game ended. Goodbye!")
            break

        # check if inputs are within valid range
        if player_input1 not in range(6) or player_input2 not in range(6):
            print("⚠️ Enter numbers between 0 and 5.\n")
            continue

        # show chosen options
        print(f"You chose: {arr_cars[player_input1]} and {arr_models[player_input2]}")

        # match logic
        if (
            (player_input1 == 0 and player_input2 == 1) or
            (player_input1 == 1 and player_input2 == 0) or
            (player_input1 == 2 and player_input2 == 2) or
            (player_input1 == 3 and player_input2 == 5) or
            (player_input1 == 4 and player_input2 == 3) or
            (player_input1 == 5 and player_input2 == 4)
        ):
            print(f"{good_match}")
            match_counter += 1
            print(f"✅ Total Matches Found: {match_counter}\n")
        else:
            print(f"{bad_match}\n")

        # check if player has found 3 matches
        if match_counter >= 3:
            print("🎉 Congratulations! You've found 3 matches and won the game!")
            break

# start the game
player_choice()