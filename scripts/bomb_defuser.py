from itertools import product

def find_phase_2_sequence():
    sequence = [1]  # The first number is given as 1
    
    # Calculate the remaining five numbers
    for i in range(1, 6):
        next_number = sequence[i - 1] * (i + 1)
        sequence.append(next_number)
    
    return sequence

def validate_phase_2_sequence(sequence):
    if sequence[0] != 1:
        return False
    
    for i in range(1, 6):
        if sequence[i] != sequence[i - 1] * (i + 1):
            return False
    
    return True

def validate_phase_3_input(local_10, local_9, local_8):
    # The README says the character must be a 'b', so return false if it is not
    if local_10 == 1 and local_9 == 'b' and local_8 == 0xd6:
        return True
    elif local_10 == 2 and local_9 == 'b' and local_8 == 0x2f3:
        return True
    elif local_10 == 7 and local_9 == 'b' and local_8 == 0x20c:
        return True
    else:
        return False

def find_phase_3_solutions():
    solutions = []
    # Define possible values of local_10 and corresponding correct values of local_9 and local_8
    conditions = {
        0: ('q', 0x309),
        1: ('b', 0xd6),
        2: ('b', 0x2f3),
        3: ('k', 0xfb),
        4: ('o', 0xa0),
        5: ('t', 0x1ca),
        6: ('v', 0x30c),
        7: ('b', 0x20c)
    }
    
    for local_10, (expected_char, expected_value) in conditions.items():
        if validate_phase_3_input(local_10, expected_char, expected_value):
            solutions.append((local_10, expected_char, expected_value))
    
    return solutions

def fibonacci(n):
    if n == 0 or n == 1:
        return 1
    a, b = 1, 1
    for _ in range(2, n + 1):
        a, b = b, a + b
    return b

def find_phase_4_solution(target_value):
    n = 0
    while True:
        fib_n = fibonacci(n)
        if fib_n == target_value:
            return n
        elif fib_n > target_value:
            return None
        n += 1

lookup_table = "isrveawhobpnutfg"

def find_phase_5_solution():
    target = "giants"
    possible_solutions = [[] for _ in range(6)]
    # A list of lists of characters that can map to the letters in 'giant':
    # i.e.:
    # possible_solutions = [
    # ['o'],        # Characters that can map to 'g'
    # ['p'],        # Characters that can map to 'i'
    # ['e', 'u'],   # Characters that can map to 'a'
    # ['k'],        # Characters that can map to 'n'
    # ['m'],        # Characters that can map to 't'
    # ['a', 'q']    # Characters that can map to 's'
    # ]

    # Collect all possible characters for each position in the target string
    for i in range(6):
        for c in range(ord('a'), ord('z') + 1):
            transformed_char = lookup_table[c & 0xf]
            if transformed_char == target[i]:
                possible_solutions[i].append(chr(c))

    # Generate all permutations of possible solutions
    # with itertools carthesian product of iterables
    all_solutions = list(product(*possible_solutions))
    return [''.join(solution) for solution in all_solutions]

def find_phase_6_solution():
    node_values = [253, 725, 301, 997, 212, 432]

    # Create a list of tuples where each tuple is (index, value)
    indexed_values = list(enumerate(node_values, start=1))
    
    # Sort the list by the value in descending order
    sorted_indexed_values = sorted(indexed_values, key=lambda x: x[1], reverse=True)
    
    # Extract the sorted indices
    sorted_indices = [index for index, value in sorted_indexed_values]
    
    return sorted_indices
    

def find_possible_final_passwords(p1, p2, p3, p4, p5, p6):
    phase1 = "".join(p1.split(" "))
    phase2 = "".join(p2.split(" "))
    phase3 = []
    for x, y, z in p3:
        phase3.append(f"{x}{y}{z}")
    phase4 = str(p4)
    phase5 = p5
    # Invert indexes 3 and 4 in phase 6 for final password (see boot2root subject)
    p6[3], p6[4] = p6[4], p6[3]
    phase6 = "".join(map(str, p6))

    all_passwords = []
    
    for p3, p5 in product(phase3, phase5):
        password = f"{phase1}{phase2}{p3}{phase4}{p5}{phase6}"
        all_passwords.append(password)
    
    return all_passwords


if __name__ == "__main__":
    print("--------------------------------------------")
    phase_1_answer = "Public speaking is very easy."
    print(f"Phase 1 answer: {phase_1_answer}")

    print("--------------------------------------------")
    phase_2_sequence = find_phase_2_sequence()
    if not validate_phase_2_sequence(phase_2_sequence):
        print(f"Phase 2 answer: not found!")
        exit(1)

    phase_2_answer = " ".join(map(str,phase_2_sequence))
    print(f"Phase 2 answer: {phase_2_answer}")

    print("--------------------------------------------")
    phase_3_solutions = find_phase_3_solutions()
    for local_10, local_9, local_8 in phase_3_solutions:
        print(f"Phase 3 possible answer: {local_10} {local_9} {local_8}")

    print("--------------------------------------------")
    target_value = 0x37 # = 55 in decimal
    phase_4_answer = find_phase_4_solution(target_value)
    print(f"Phase 4 answer: {phase_4_answer}")

    print("--------------------------------------------")
    phase_5_solutions = find_phase_5_solution()
    for solution in phase_5_solutions:
        print(f"Phase 5 possible answer: {solution}")

    print("--------------------------------------------")
    phase_6_solution = find_phase_6_solution()
    phase_6_answer = " ".join(map(str,phase_6_solution))
    print(f"Phase 6 answer: {phase_6_answer}")

    print("--------------------------------------------")
    passwords = find_possible_final_passwords(phase_1_answer, phase_2_answer, phase_3_solutions, phase_4_answer, phase_5_solutions, phase_6_solution)
    for password in passwords:
        print(f"Possible password: {password}")

    print("--------------------------------------------")
    print(f"Tested final working password: {passwords[1]}")