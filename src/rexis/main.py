from rexis.operations.populate_db import fetch_malware_documents, index_documents


def main():
    samples = fetch_malware_documents(query_type="tag",
        query_value="ransomware",)
    if samples:
        index_documents(samples)

if __name__ == "__main__":
    main()
