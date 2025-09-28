#!/usr/bin/python3

# Game -> Match the car with its model

# print statements that creates a banner
print('########################################')
print('#                                      #')
print('#                                      #')
print('#        WELCOME! LETS BEGIN           #')
print('#      MATCH THE CAR MAKE & MODEL      #')
print('#                                      #')
print('#                                      #')
print('########################################')
print('')

# array of cars, model, and year
arr_cars = ["Genesis", "Audi", "BMW", "Cadilac", "Mercedes-AMG", "Acura"]
arr_models = ["RS3", "G70", "M3", "C63", "Type S", "CT4-V"]
arr_engine = ''
arr_horsepower = []
arr_year = [2023, 2022, 2021]
good_match = "You found a match!"
bad_match = "Try again"

#print("Enter -1 to Quit")
#print('')

# function that runs the program
def player_choice():
    while True:
        try:
            # get player input
            print("Enter 2 numbers between 0 and 5")
            print('')
            player_input1 = int(input("First Number: "))
            print(arr_cars[player_input1])
            print('')
            player_input2 = int(input("Second Number: "))
            print(arr_models[player_input2])
            print('')
        except ValueError:
            print("Enter numbers only.")
            print('')
            continue
        
        # check if inputs are within valid range
        if player_input1 not in range(6) or player_input2 not in range(6):
            print("Enter numbers between 0 and 5.")
            continue
        
        # exit game
        if player_input1 == 9 or player_input2 == 9:
            print("Game ended. Goodbye!")
            break

        # match logic
        if player_input1 == 0 and player_input2 == 1:
            print(f"{arr_cars[0]} {arr_models[1]}\n{good_match}")
            print('')
        elif player_input1 == 1 and player_input2 == 0:
            print(f"{arr_cars[1]} {arr_models[0]}\n{good_match}")
            print('')
        elif player_input1 == 2 and player_input2 == 2:
            print(f"{arr_cars[2]} {arr_models[2]}\n{good_match}")
            print('')
        elif player_input1 == 3 and player_input2 == 5:
            print(f"{arr_cars[3]}{arr_models[5]}\n{good_match}")
            print('')
        elif player_input1 == 4 and player_input2 == 3:
            print(f"{arr_cars[4]} {arr_models[3]}\n{good_match}")
            print('')
        elif player_input1 == 5 and player_input2 == 4:
            print(f"{arr_cars[5]} {arr_models[4]}\n{good_match}")
            print('')

        else:
            print(bad_match)

# call the function to start the game
player_choice()