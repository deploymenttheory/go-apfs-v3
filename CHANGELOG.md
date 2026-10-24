# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0](https://github.com/deploymenttheory/go-apfs-v3/compare/v0.1.0...v0.2.0) (2026-10-24)


### Features

* **apfs:** create native clones through ordinary copy commands ([8dd473a](https://github.com/deploymenttheory/go-apfs-v3/commit/8dd473ad4db20fb3e80e8cdffadb8e6ddcfd9bbc))
* **apfs:** edit shared clone streams with copy-on-write ownership ([1705c1b](https://github.com/deploymenttheory/go-apfs-v3/commit/1705c1b4e706b55700a5c7124452df16bfb45a8b))
* **copy:** retain clone stream intent through logical edits ([a6d9f50](https://github.com/deploymenttheory/go-apfs-v3/commit/a6d9f50d6abebc7fafaa56dda5bf994e126dea59))
* **diskimage:** decode bounded LZFSE UDIF chunks ([0482c48](https://github.com/deploymenttheory/go-apfs-v3/commit/0482c48072754e0b8bc31cad1205e67b40b396d2))
* **diskimage:** decode bounded LZFSE UDIF chunks ([abea1a6](https://github.com/deploymenttheory/go-apfs-v3/commit/abea1a6727f2baf27ce05aac95c9188b5274af97))
* **diskimage:** read bounded LZFSE UDIF chunks ([d3b00c9](https://github.com/deploymenttheory/go-apfs-v3/commit/d3b00c960c775ebf3262e7f8d29bcd1dd1c3e5ac))
* edit existing APFS clones and encrypted disk images ([38f949f](https://github.com/deploymenttheory/go-apfs-v3/commit/38f949fe1b6e40e4980077d882ccb010ec3528ac))
* **filesystem:** declare explicit per-stream clone lineage ([3d34869](https://github.com/deploymenttheory/go-apfs-v3/commit/3d348695e4e881e6d5755b0cfc5574ad1b85f7b4))
* **filesystem:** retain captured partial clone stream identity ([7294564](https://github.com/deploymenttheory/go-apfs-v3/commit/72945647a4411be214617cd49140fd69f2386360))
* **filesystem:** validate clone lineage and expose partial sharing ([93c1863](https://github.com/deploymenttheory/go-apfs-v3/commit/93c18632556bc865d0c55b3875c9684ba15a73ff))
* **pack:** materialize explicit APFS clone stream sharing ([47b44b6](https://github.com/deploymenttheory/go-apfs-v3/commit/47b44b6317a7d3dbe3642f209c1ce373d5813629))
* preserve APFS clone sharing through copy and sessions ([7566f10](https://github.com/deploymenttheory/go-apfs-v3/commit/7566f1030c628e950564dd29b0e0fc3339cca6e4))
* **session:** persist explicit clone stream relationships ([ef1dc03](https://github.com/deploymenttheory/go-apfs-v3/commit/ef1dc03b5e3fb2fe98889c332c894d5630b8a3a2))


### Bug Fixes

* **acceptance:** bind APFS inventory to the observed device ([0681da3](https://github.com/deploymenttheory/go-apfs-v3/commit/0681da365cc66de78889919b8a386b2f79a60c3f))
* **acceptance:** bind every image cleanup to its owner ([e510ae7](https://github.com/deploymenttheory/go-apfs-v3/commit/e510ae7cca79f5d783c3fc40d432149be0d4c7e5))
* **acceptance:** bound fixture image lifetimes and verify platform gates ([4a55ce4](https://github.com/deploymenttheory/go-apfs-v3/commit/4a55ce4ab52088f10f566f774a9f5f9b84035392))
* **acceptance:** declare raw input when re-encrypting native edits ([f3fdbc2](https://github.com/deploymenttheory/go-apfs-v3/commit/f3fdbc2681980d76423067d0bd5e95aef537403a))
* **acceptance:** guard approved volume unmount dissent ([b7d0b35](https://github.com/deploymenttheory/go-apfs-v3/commit/b7d0b358a9ecc589397ede36727d8d9e54086ae0))
* **acceptance:** guard native attachment and mount cleanup ([0f267b3](https://github.com/deploymenttheory/go-apfs-v3/commit/0f267b340d67050a43be68b4aebf09fc18f8b657))
* **acceptance:** keep native verification progressing ([e79016e](https://github.com/deploymenttheory/go-apfs-v3/commit/e79016e11ffa9e8c65e2e42363afaf107b49329c))
* **acceptance:** normalize host paths before resource-fork detection ([d4b7e6f](https://github.com/deploymenttheory/go-apfs-v3/commit/d4b7e6fe461048dae94909882636303bdfc764ae))
* **acceptance:** pin snapshot mount identity during cleanup ([36b6eac](https://github.com/deploymenttheory/go-apfs-v3/commit/36b6eac71621f7e7e8f9a8698186fc945b837acd))
* **acceptance:** preserve native cleanup failures and evidence ([5fd3fb9](https://github.com/deploymenttheory/go-apfs-v3/commit/5fd3fb9c0d0d406413cd206eb9a9fdb49bbb3a9c))
* **acceptance:** release run-owned fixture images after readers close ([1d84df5](https://github.com/deploymenttheory/go-apfs-v3/commit/1d84df572690dad74adae03d70f335848aa0cc6d))
* **acceptance:** retain failed output verification commands ([c445f31](https://github.com/deploymenttheory/go-apfs-v3/commit/c445f31f2b3d1d7284c5ed77416c7cbb2c98ff90))
* **acceptance:** retry transient busy snapshot unmount ([69add77](https://github.com/deploymenttheory/go-apfs-v3/commit/69add77ba53f7c6b6f4062500e825bc0bd77aad0))
* **acceptance:** share guarded image operation retries ([4e0e767](https://github.com/deploymenttheory/go-apfs-v3/commit/4e0e767234000af2dd65405a384f5fb01708e9f3))
* **acceptance:** share image lifecycle retries on macOS 26+ ([ffbe16c](https://github.com/deploymenttheory/go-apfs-v3/commit/ffbe16c46014db1cbaad0fb413ecb12b20d57033))
* **acceptance:** size native continuations and retain busy evidence ([589a9c4](https://github.com/deploymenttheory/go-apfs-v3/commit/589a9c45c07235d6988336971f188fae026aa633))
* **acceptance:** wait for partitioned image volume slices ([eb44317](https://github.com/deploymenttheory/go-apfs-v3/commit/eb443176224a457f46e4055d0ecaece9bc48c80c))
* **acceptance:** wait for partitioned image volume slices ([2531804](https://github.com/deploymenttheory/go-apfs-v3/commit/2531804a03741a141eb9ec6603f45c2687a32ccb))
* **apfs:** require inode stream ownership before replacement or release ([39623d1](https://github.com/deploymenttheory/go-apfs-v3/commit/39623d1672188112947fb8a71cf2fdbc2da144fc))
* **apfs:** reserve checkpoint capacity for ephemeral growth ([a347955](https://github.com/deploymenttheory/go-apfs-v3/commit/a3479556d1b3fa1529afc4b1cd22681644ccca0e))
* **apfs:** retain owned empty clone stream identity during capture ([1d51046](https://github.com/deploymenttheory/go-apfs-v3/commit/1d51046208c13cf1b31eb230b2b84ad3d2231539))
* **apfs:** size checkpoints for allocator growth and qualify workflows ([81eca7f](https://github.com/deploymenttheory/go-apfs-v3/commit/81eca7fdebbc0ec4af9f4246821d5296411ed489))
* **copy:** preserve untouched source ACL clone lineage ([5a2bb0a](https://github.com/deploymenttheory/go-apfs-v3/commit/5a2bb0a4cd39e1f5b1427aec53ce3bcde68f0e46))
* **copy:** retain native alias clocks and symlink ACL creation policy ([c7fc0cb](https://github.com/deploymenttheory/go-apfs-v3/commit/c7fc0cbcc8464f6b035ba6d3e43d596c2f89e226))
* **decmpfs:** decode type-4 zlib blocks with resource suffix ([59da994](https://github.com/deploymenttheory/go-apfs-v3/commit/59da9942d5aa6ec994543c37c1a72291dd0e4245))
* **decmpfs:** decode type-4 zlib blocks with resource suffix ([7a26153](https://github.com/deploymenttheory/go-apfs-v3/commit/7a26153eb16526457e79376c10c2b6c4a7e0dd37))
* **fixture:** bind legacy kernel disk-image owners explicitly ([685d5a2](https://github.com/deploymenttheory/go-apfs-v3/commit/685d5a21f818cd6d613c6c661e170351a853c26a))
* **fixture:** distinguish ownership from completed attachment cleanup ([86f4f9e](https://github.com/deploymenttheory/go-apfs-v3/commit/86f4f9e9ea48d2db7357429b8a0ea3912eb9d3ed))
* **fixture:** project ownership from opaque registry archives ([2a6bb49](https://github.com/deploymenttheory/go-apfs-v3/commit/2a6bb49f2b809efc3ac23c98a820e71852298b82))
* **fixture:** refuse release while the expected image remains attached ([85d864b](https://github.com/deploymenttheory/go-apfs-v3/commit/85d864b85401573e8ced2cb13b7949ff2a10cb27))
* **fixture:** require kernel proof for missing image ownership ([b313b25](https://github.com/deploymenttheory/go-apfs-v3/commit/b313b25502422e06400eace75e4b6b138607fdfd))
* **fixture:** retain related attachment failure evidence ([962d696](https://github.com/deploymenttheory/go-apfs-v3/commit/962d696e220a12e43369e63acac833c91757ff19))
* **fixture:** separate native image paths from host resolution ([bdeaf76](https://github.com/deploymenttheory/go-apfs-v3/commit/bdeaf76a19c4566e001b4f92106f9893767664f6))
* **imageedit:** bind clone outcomes to the actual publication ([dd1aabc](https://github.com/deploymenttheory/go-apfs-v3/commit/dd1aabc90feee9f793e0a23e0daf52effaa7285f))
* **imageedit:** report clones only after image publication ([f928ab7](https://github.com/deploymenttheory/go-apfs-v3/commit/f928ab7a2e985048aed85055d43e0f2464fd7a82))
* **imageedit:** retain clone outcomes for visible completed outputs ([8f4bc59](https://github.com/deploymenttheory/go-apfs-v3/commit/8f4bc59e94100498736a1a20be244fcd106f5335))
* **pack:** reconcile clone descriptors before compression ([8a64efb](https://github.com/deploymenttheory/go-apfs-v3/commit/8a64efb9cdf3dec58f41cbad4fcdf561cc40c703))
* **pack:** validate source clone groups before storage transforms ([c369399](https://github.com/deploymenttheory/go-apfs-v3/commit/c369399b4fbcd2c04d3f75d2d2886a56c3a197be))
* **session:** release exclusive locks before closing inherited descriptors ([1cd0833](https://github.com/deploymenttheory/go-apfs-v3/commit/1cd083389d77bfaaca073d9e3da81ed6537f042e))
* **session:** report clones only after successful publication ([246e017](https://github.com/deploymenttheory/go-apfs-v3/commit/246e01711ee5c103fa9d9d8c2cfa8e2b1302416c))

## 1.0.0 (2026-10-21)


### Features

* **acceptance:** build the Apple-only fixture capture tool ([#112](https://github.com/deploymenttheory/go-apfs-v3/issues/112)) ([e165aa4](https://github.com/deploymenttheory/go-apfs-v3/commit/e165aa4d760a4d8c73f9e652e48216a9622b2205))
* **acceptance:** define fixture recipes and the observation schema ([#111](https://github.com/deploymenttheory/go-apfs-v3/issues/111)) ([7fe6241](https://github.com/deploymenttheory/go-apfs-v3/commit/7fe62415cb148d87048027b23b6e2e12433c055f))
* **acceptance:** portable conformance and native verification tiers ([#115](https://github.com/deploymenttheory/go-apfs-v3/issues/115)) ([5cdd6b8](https://github.com/deploymenttheory/go-apfs-v3/commit/5cdd6b84eccd7cb04e96537675cf2672a20d3c22))
* **acceptance:** publish the fixture corpus as release assets with a lock file ([#113](https://github.com/deploymenttheory/go-apfs-v3/issues/113)) ([3fa6af9](https://github.com/deploymenttheory/go-apfs-v3/commit/3fa6af927aab396188df95f064752cb831782680)), closes [#103](https://github.com/deploymenttheory/go-apfs-v3/issues/103)
* add file commands with persistent managed sessions ([#19](https://github.com/deploymenttheory/go-apfs-v3/issues/19)) ([10f3f1d](https://github.com/deploymenttheory/go-apfs-v3/commit/10f3f1da54e9a9a85ee1970679d9fd35c8845ed6))
* add native name lookup, hard links and HFS+ overflow extents ([#9](https://github.com/deploymenttheory/go-apfs-v3/issues/9)) ([547b627](https://github.com/deploymenttheory/go-apfs-v3/commit/547b62706d43311360207a63791ed59f1add4ed0))
* add preservation-aware copying into existing filesystem images ([#34](https://github.com/deploymenttheory/go-apfs-v3/issues/34)) ([9549e48](https://github.com/deploymenttheory/go-apfs-v3/commit/9549e48cf1074420bf6c2c3d87c8a6b635caf4d6))
* add read-only APFS and HFS+ foundation ([#7](https://github.com/deploymenttheory/go-apfs-v3/issues/7)) ([6735bf8](https://github.com/deploymenttheory/go-apfs-v3/commit/6735bf8d6a11cd0daea4ad2dc283b6d64cce400e))
* **apfs:** account retained storage before block reuse ([#75](https://github.com/deploymenttheory/go-apfs-v3/issues/75)) ([c125ee5](https://github.com/deploymenttheory/go-apfs-v3/commit/c125ee5e724f364352e4c80434f3286f870216d6))
* **apfs:** read retained snapshots as historical filesystem views ([#13](https://github.com/deploymenttheory/go-apfs-v3/issues/13)) ([58e3a36](https://github.com/deploymenttheory/go-apfs-v3/commit/58e3a3653840f01e3099f9bce3d56aad80f54c75))
* build APFS containers with multiple volumes and groups ([#23](https://github.com/deploymenttheory/go-apfs-v3/issues/23)) ([09a742d](https://github.com/deploymenttheory/go-apfs-v3/commit/09a742ddccd6b1c7b82dc252a7bc9192aa34e7fd))
* build deterministic APFS images ([#22](https://github.com/deploymenttheory/go-apfs-v3/issues/22)) ([5637f6c](https://github.com/deploymenttheory/go-apfs-v3/commit/5637f6c04ba13fe9950a21550a0aa349e8d6775a))
* build deterministic HFS+ and HFSX DMGs ([#20](https://github.com/deploymenttheory/go-apfs-v3/issues/20)) ([5785d25](https://github.com/deploymenttheory/go-apfs-v3/commit/5785d2526d7f4d4311a7fd1f96fd9689af7322a0))
* **ci:** reuse reviewed Apple inputs and complete qualification evidence ([#92](https://github.com/deploymenttheory/go-apfs-v3/issues/92)) ([1677b69](https://github.com/deploymenttheory/go-apfs-v3/commit/1677b6981dd0101683772d3d4f44552e616563e1))
* **ci:** share reviewed Apple inputs across complete qualification ([#93](https://github.com/deploymenttheory/go-apfs-v3/issues/93)) ([92736ce](https://github.com/deploymenttheory/go-apfs-v3/commit/92736cea67e4ccee7a830f68472bc1cb8ab4dd34))
* create and repack encrypted DMG images ([#24](https://github.com/deploymenttheory/go-apfs-v3/issues/24)) ([10cd439](https://github.com/deploymenttheory/go-apfs-v3/commit/10cd439c522947f8cebbe1b9644d04cbc34a1f60))
* create links in existing filesystem images ([#33](https://github.com/deploymenttheory/go-apfs-v3/issues/33)) ([aa96d9a](https://github.com/deploymenttheory/go-apfs-v3/commit/aa96d9a9e4af26d8cb87d5804a4fa49edca558ba))
* **diskimage:** read password-protected DMG images ([#12](https://github.com/deploymenttheory/go-apfs-v3/issues/12)) ([0512d84](https://github.com/deploymenttheory/go-apfs-v3/commit/0512d84909a44ccd2ad97df738548805a25a2624))
* edit existing APFS files through copy-on-write transactions ([#30](https://github.com/deploymenttheory/go-apfs-v3/issues/30)) ([98096c3](https://github.com/deploymenttheory/go-apfs-v3/commit/98096c351c441f1858bc3eb4753bb83424236e2c))
* edit existing HFS filesystems in transactional output copies ([#27](https://github.com/deploymenttheory/go-apfs-v3/issues/27)) ([5ea782d](https://github.com/deploymenttheory/go-apfs-v3/commit/5ea782d8576576c9423a23075e26622bb26a32ed))
* edit files and directories in existing HFS images ([#29](https://github.com/deploymenttheory/go-apfs-v3/issues/29)) ([bb65337](https://github.com/deploymenttheory/go-apfs-v3/commit/bb653370281b438946c297e271a60190cdfb3eab))
* extend offline image editing and qualify native semantics ([#37](https://github.com/deploymenttheory/go-apfs-v3/issues/37)) ([294eb06](https://github.com/deploymenttheory/go-apfs-v3/commit/294eb06b91c6e3277d55ae5d5da7f7d44cba5514))
* preserve empty HFS journals during existing-image edits ([#28](https://github.com/deploymenttheory/go-apfs-v3/issues/28)) ([c9ad694](https://github.com/deploymenttheory/go-apfs-v3/commit/c9ad6943c253d162dd41740cc35dc4f281a93d6b))
* read compressed APFS and HFS+ files with native qualification ([#10](https://github.com/deploymenttheory/go-apfs-v3/issues/10)) ([6791bf9](https://github.com/deploymenttheory/go-apfs-v3/commit/6791bf9b97cc729e601faa3b103d69f397cf1a5f))
* recover interrupted APFS checkpoints into new images ([#36](https://github.com/deploymenttheory/go-apfs-v3/issues/36)) ([f9672bc](https://github.com/deploymenttheory/go-apfs-v3/commit/f9672bcdfbb5857e4647370a0cab003c6a0a6752))
* recover interrupted HFS journals into new images ([#35](https://github.com/deploymenttheory/go-apfs-v3/issues/35)) ([906ae60](https://github.com/deploymenttheory/go-apfs-v3/commit/906ae600619a37cf67f52bf47790fdd5df61e72c))
* repack disk images without changing sectors ([#21](https://github.com/deploymenttheory/go-apfs-v3/issues/21)) ([262d1c7](https://github.com/deploymenttheory/go-apfs-v3/commit/262d1c74d77371f7c4c60886b1896853d91c47c3))
* support existing APFS file and directory operations ([#31](https://github.com/deploymenttheory/go-apfs-v3/issues/31)) ([088f51c](https://github.com/deploymenttheory/go-apfs-v3/commit/088f51ccf3ae23a2548fea44c45b099f3649978a))
* support existing-image metadata and attribute editing ([#32](https://github.com/deploymenttheory/go-apfs-v3/issues/32)) ([cf13118](https://github.com/deploymenttheory/go-apfs-v3/commit/cf13118a4ab93007238dc6c9fb42129852736b98))
* **workspace:** edit directory trees in ordered batches ([#17](https://github.com/deploymenttheory/go-apfs-v3/issues/17)) ([02d09c3](https://github.com/deploymenttheory/go-apfs-v3/commit/02d09c3dfc0e574247f10ad6eb259c6851c45dd1))
* **workspace:** edit metadata, attributes and resource forks ([#18](https://github.com/deploymenttheory/go-apfs-v3/issues/18)) ([bca78ea](https://github.com/deploymenttheory/go-apfs-v3/commit/bca78ead48a3752fe16b458e82485793ecd71634))
* **workspace:** preserve extracted macOS files and metadata ([#14](https://github.com/deploymenttheory/go-apfs-v3/issues/14)) ([f73344e](https://github.com/deploymenttheory/go-apfs-v3/commit/f73344e62eaddf97106bad7e5ae7389cbe3998bd))
* **workspace:** replace contents while preserving macOS metadata ([#16](https://github.com/deploymenttheory/go-apfs-v3/issues/16)) ([2fe04d3](https://github.com/deploymenttheory/go-apfs-v3/commit/2fe04d31dd0db6d60fb12a946a6071bb30d29270))
* write transparent file compression for image builds ([#25](https://github.com/deploymenttheory/go-apfs-v3/issues/25)) ([b7befa5](https://github.com/deploymenttheory/go-apfs-v3/commit/b7befa5fb746fb0d37d44c4285f87f48a68bb6a6))


### Bug Fixes

* **acceptance:** accept verified concurrent Windows cache publication ([62a88cb](https://github.com/deploymenttheory/go-apfs-v3/commit/62a88cb782296f78de4dd6c5c19c74e40d62aaac))
* **acceptance:** build the darwin host volume for the native verifier and vet the native tag alone ([6ea5d94](https://github.com/deploymenttheory/go-apfs-v3/commit/6ea5d94276ea66fe9f8e8d90273c7bc83f27bf53))
* **acceptance:** correct the native verifier's comparisons, credentials, continuation and parallelism ([074c630](https://github.com/deploymenttheory/go-apfs-v3/commit/074c6301b9673ac5ddcad8a67c760f46c0e6515e))
* **acceptance:** hash devices to their end, retry a lagging APFS listing, and keep native parallelism at three ([1e32854](https://github.com/deploymenttheory/go-apfs-v3/commit/1e32854c7b2f7d8be1903406c6ece2fb605993ea))
* **acceptance:** isolate capture caches and retain rejected journal windows ([410e0a4](https://github.com/deploymenttheory/go-apfs-v3/commit/410e0a4b89aec59a1975c7674afe39d980581d21))
* **acceptance:** reuse completed raw fixture expansions ([00befc5](https://github.com/deploymenttheory/go-apfs-v3/commit/00befc505473eb2cbedf43707a2bcad923733808))
* **acceptance:** wait for diskutil to discover an attached image's volumes, never observe an empty list ([20e05a6](https://github.com/deploymenttheory/go-apfs-v3/commit/20e05a61783ad70e0fc02c4455543880e6972b58))
* **apfs:** read completed encryption transitions with native lifecycle controls ([#73](https://github.com/deploymenttheory/go-apfs-v3/issues/73)) ([e961de5](https://github.com/deploymenttheory/go-apfs-v3/commit/e961de519178bee3ef0f0493195e8661ac9d0a78))
* **ci:** publish completed independent Apple reference refreshes ([#96](https://github.com/deploymenttheory/go-apfs-v3/issues/96)) ([2bd3e7a](https://github.com/deploymenttheory/go-apfs-v3/commit/2bd3e7a3ffb1d9a2883dc7df7c2ad09bdd778cc6))
* **fixture:** compile on Windows, record APFS quota and reserve, retain every stage, retry a busy create ([#125](https://github.com/deploymenttheory/go-apfs-v3/issues/125)) ([6100297](https://github.com/deploymenttheory/go-apfs-v3/commit/6100297f709f1d17ee3f8d27bab3337bf20cb87a))
* **fixture:** confirm a mount through the kernel, not diskutil's view ([64e4de8](https://github.com/deploymenttheory/go-apfs-v3/commit/64e4de8cf927e8c09b8cfbfd852d506aee1fcc07))
* **fixture:** identify an attached image's own disk by its partition-scheme content ([db9f507](https://github.com/deploymenttheory/go-apfs-v3/commit/db9f507e991b385713e5e259c3db8807f332b191))
* **fixture:** retry a busy detach only while the device still belongs to the image ([feec4d2](https://github.com/deploymenttheory/go-apfs-v3/commit/feec4d20788e191694712ead62c4eb9747334831))
* **imageedit:** copy into volumes of any size by reading only what the copy touches ([#133](https://github.com/deploymenttheory/go-apfs-v3/issues/133)) ([4bb898c](https://github.com/deploymenttheory/go-apfs-v3/commit/4bb898c24eb4c82c09272f091fce239ee7a1c5ab))
* isolate HFS copy deadlines within the existing family job ([#52](https://github.com/deploymenttheory/go-apfs-v3/issues/52)) ([525f497](https://github.com/deploymenttheory/go-apfs-v3/commit/525f497a436bbee6cf0d679d9e6928fd3ec35dbf))
* prepare sparse image-editing scratch and retain qualification evidence ([#54](https://github.com/deploymenttheory/go-apfs-v3/issues/54)) ([0065fa9](https://github.com/deploymenttheory/go-apfs-v3/commit/0065fa987bce2b93de4131c3c2b87d7b204120d4))
* retain bounded diagnostics for failed native image creation ([#53](https://github.com/deploymenttheory/go-apfs-v3/issues/53)) ([62eb115](https://github.com/deploymenttheory/go-apfs-v3/commit/62eb1150e214681e168a389c606331e830163b3b))
* verify newly created APFS directory statistics ([#38](https://github.com/deploymenttheory/go-apfs-v3/issues/38)) ([79e4dde](https://github.com/deploymenttheory/go-apfs-v3/commit/79e4dde4d2b8a843422de3a91d47db67feba1640))

## [Unreleased]

### Added

- Added xyz [@your_username](https://github.com/your_username)

### Fixed

- Fixed zyx [@your_username](https://github.com/your_username)

## [1.1.0] - 2021-06-23

### Added

- Added x [@your_username](https://github.com/your_username)

### Changed

- Changed y [@your_username](https://github.com/your_username)

## [1.0.0] - 2021-06-20

### Added

- Inititated y [@your_username](https://github.com/your_username)
- Inititated z [@your_username](https://github.com/your_username)
