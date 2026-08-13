## Create with the console

1. Sign in at [the user console](/user/).
2. Choose the Workspace that will own the resource.
3. Create a Cat with a lowercase name, exact `sha256:` boot-image digest, CPU, memory, RootDisk size, and durability.
4. Keep the returned Cat and Operation IDs. The console can list and inspect the current projection.

Cat create is browser-persistent. If the server commits but the response is lost, reload or refresh replays the exact path, canonical body, and Idempotency-Key.

The console also creates PersistentDisks. Its closed durability default is Strict, and the request explicitly contains `durability`, `name`, and `size_bytes`.

## Create with the CLI

    cats login
    cats create dev +      --boot-image-digest sha256:<64-lowercase-hex> +      --cpus 2 +      --memory 2GiB +      --root-size 1GiB +      --durability strict
    cats ls
    cats get cat_…
    cats operation wait op_…

Use immutable IDs for item reads. During the signed runtime cutover, lifecycle, Guest command, deployment, Endpoint, and delete mutations are not shipped. Do not substitute examples from an older client.
