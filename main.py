from equipement import Equipment

name, port = input("<name> <port>\n").split()
port = int(port)

equipment = Equipment(name, port)

print(equipment)
