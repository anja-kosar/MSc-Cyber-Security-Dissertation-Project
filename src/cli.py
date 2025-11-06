# src/cli.py
# Simple runner to execute all modules in order

from src import nazario, images, urlscan, summarize

def main():
    print("\nRunning Nazario scan...")
    nazario.main()

    print("\nRunning Image OCR scan...")
    images.main()

    print("\nRunning URL scan...")
    urlscan.main()

    print("\nCreating summary...")
    summarize.main()

    print("\n✅  All modules finished successfully.")

if __name__ == "__main__":
    main()
