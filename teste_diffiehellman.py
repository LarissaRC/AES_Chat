users = ["A", "B", "C"]

for i in range(len(users)):
    print(f"User {i+1}:")
    for j in range(len(users)):
        print(f"- {users[(i + j) % len(users)]}")