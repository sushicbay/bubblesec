def parse_zeek_log(file_path):

    records = []
    fields = []

    with open(file_path) as f:

        for line in f:

            if line.startswith("#fields"):
                fields = line.strip().split()[1:]

            elif not line.startswith("#"):

                values = line.strip().split("\t")

                if len(values) == len(fields):
                    record = dict(zip(fields, values))
                    records.append(record)

    return records