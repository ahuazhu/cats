## 使用控制台 Create

1. 在[用户控制台](/user/)登录。
2. 选择拥有该资源的 Workspace。
3. 使用小写名称、CPU、Memory、RootDisk Size 与 Durability 创建 Cat；Control 会自动选择当前已资格化的 Boot Image。
4. 保存返回的 Cat 与 Operation ID。控制台可以 List 并 Inspect 当前 Projection。

Cat Create 使用浏览器持久化。若服务端已 Commit 但响应丢失，Reload 或 Refresh 会重放完全相同的 Path、Canonical Body 与 Idempotency-Key。

控制台也能创建 PersistentDisk。它的 Closed Durability Default 是 Strict，Request 明确包含 `durability`、`name` 与 `size_bytes`。

## 使用 CLI Create

    cats login
    cats create dev --cpus 2 --memory 2GiB --root-size 1GiB --durability strict
    cats ls
    cats get cat_…
    cats operation wait op_…

Item Read 必须使用不可变 ID。Signed Runtime Cutover 期间不发布 Lifecycle、Guest Command、Deployment、Endpoint 与 Delete Mutation。不要替换为旧版 Client 的示例。
