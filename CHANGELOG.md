# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 1.0.0 (2026-10-17)


### Features

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

* **apfs:** read completed encryption transitions with native lifecycle controls ([#73](https://github.com/deploymenttheory/go-apfs-v3/issues/73)) ([e961de5](https://github.com/deploymenttheory/go-apfs-v3/commit/e961de519178bee3ef0f0493195e8661ac9d0a78))
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
