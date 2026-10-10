"""Compare portable output bytes before qualifying them with Apple tools."""
from capture import sha256
from verify_preservation import require


def verify_identical_outputs(images, verify_one):
    # The host outputs must be byte-identical before native verification. One
    # Apple check then qualifies those exact bytes for every portable producer.
    digests = [sha256(image) for image in images]
    require(images and len(set(digests)) == 1, 'hosts produced different image bytes')
    digest, entries = verify_one(images[0])
    require(digest == digests[0], 'image changed between host comparison and native check')
    print(f'Qualified {len(images)} identical host outputs via {images[0]}', flush=True)
    return entries

