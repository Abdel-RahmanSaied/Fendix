# Scan fixture, not a real app. The deliberate finding lives in the
# Dockerfile (unpinned base image); this file just makes the fixture look
# like a Python project to a --code scan.
def main():
    print("fixture")


if __name__ == "__main__":
    main()
