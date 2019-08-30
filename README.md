`pkimap` is a certificate authority discovery script.

It accepts a single CA certificate (typically a root CA) and outputs a CSV file describing the certificates discovered, which can then be imported into a nice spreadsheet. Certificates are recursively examined, extracting URLs and downloading PKCS#7 bundles, which contain issued CA certificates.

There are two major caveats. First, the X.509v3 fields we are looking at are common, but optional. Second, we are depending on the CA to actually update the files we download, which may not be an immediate or automated process.

