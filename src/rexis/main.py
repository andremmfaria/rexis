from rexis.operations.populate_db import populate_db


def main():
    populate_db(
        query_type="tag",
        query_value="ransomware",
    )

if __name__ == "__main__":
    main()
