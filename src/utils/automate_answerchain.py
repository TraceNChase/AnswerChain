import subprocess
import time
import sys

# Path to main.py
main_path = r"C:\Users\deskt\Desktop\Project_SECQ_CLI\AnswerChain\src\main.py"

# Define the 14 questions with their texts, number of alternatives, and alternatives lists
questions = [
    ("First pet?", 5, ["Rex", "Mia", "Ziv", "Bo", "Puck"]),
    ("Fav color?", 6, ["Tan", "Cyan", "Moss", "Rose", "Onyx", "Lilac"]),
    ("Birth city?", 7, ["Lima", "Riga", "Oslo", "Pune", "Doha", "Minsk", "Bonn"]),
    ("First car?", 8, ["Saab", "VW", "Ford", "Mini", "Kia", "Seat", "Audi", "Lada"]),
    ("Lucky number?", 9, ["7", "13", "21", "42", "88", "3", "9", "27", "99"]),
    ("Childhood toy?", 5, ["Kite", "Lego", "Yo-yo", "Bear", "Robot"]),
    ("School mascot?", 6, ["Wolf", "Shark", "Falcon", "Ox", "Dragon", "Bee"]),
    ("Street lived?", 7, ["Elm", "Oak", "Pine", "Hill", "Lake", "Maple", "King"]),
    ("Mother mid name?", 8, ["Ann", "Mae", "Lyn", "Joy", "Sue", "Eve", "Lux", "Rae"]),
    ("Best friend?", 9, ["Max", "Zoe", "Arun", "Kim", "Nia", "Tom", "Leo", "Ira", "Bea"]),
    ("Dream job?", 5, ["Pilot", "Chef", "Coder", "Nurse", "Judge"]),
    ("First concert?", 6, ["ABBA", "Muse", "Blur", "Korn", "Tool", "Kiss"]),
    ("Fav fruit?", 7, ["Fig", "Pear", "Plum", "Lime", "Kiwi", "Mango", "Date"]),
    ("Secret hobby?", 5, ["Ski", "Bake", "Chess", "Code", "Run"]),
]

# Build the sequence of all input lines
all_inputs = []
all_inputs.append("1\n")  # Step 2: Main menu - Enter setup phase
all_inputs.append("1\n")  # Step 3: Setup menu - Create new security questions

for i, (qtext, num_alts, alts) in enumerate(questions):
    all_inputs.append(qtext + "\n")  # Question text
    all_inputs.append(str(num_alts) + "\n")  # Number of alternatives
    for alt in alts:
        all_inputs.append(alt + "\n")  # Each alternative
    all_inputs.append("\n")  # Step X: Select question type (Standard - Enter)
    all_inputs.append("A B C\n")  # Mark correct answers (A B C)
    all_inputs.append("\n")  # Re-edit choice (Enter)
    if i == len(questions) - 1:
        all_inputs.append("d\n")  # Step 101: Navigation after last question - Done
    else:
        all_inputs.append("n\n")  # Navigation - Next question

all_inputs.append("j\n")  # Step 103: Save questions (j for JSON and text)

# Launch the subprocess for main.py and automate inputs
print("Launching main.py and starting automation...")
print("This will simulate the full workflow with minimal delays for real-time feel.")

with subprocess.Popen(
    [sys.executable, main_path],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    bufsize=1,
    universal_newlines=True
) as proc:
    for inp in all_inputs:
        proc.stdin.write(inp)
        proc.stdin.flush()
        time.sleep(0.05)  # Small delay to simulate real-time input (as fast as possible without being instant)
    
    # Wait for the process to complete and capture output
    stdout, stderr = proc.communicate()
    
    print("\nAutomation completed successfully.")
    print("\nProcess return code:", proc.returncode)
    if proc.returncode == 0:
        print("STDOUT output (summary and any messages):")
        print(stdout)
    else:
        print("STDERR (if any errors):")
        print(stderr)
        print("Note: If return code != 0, check the application logs or inputs.")