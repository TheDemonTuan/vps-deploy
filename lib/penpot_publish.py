"""Publish only a same-run, smoke-tested native four-image build artifact."""
import hashlib
from pathlib import Path

from core import HASH, PENPOT_REPOSITORIES, SHA, docker, image_map, inspect, require
from operations import anonymous_image


def release_record(record, source, platform, expected_images):
    require(type(source) is str and SHA.fullmatch(source) and type(platform) is str and SHA.fullmatch(platform),
            'PENPOT_BUILD_IDENTITY')
    require(type(record) is dict and set(record) == {
        'schemaVersion', 'sourceSha', 'platformRef', 'platform', 'images'}, 'PENPOT_RELEASE_ARTIFACT')
    require(type(record['schemaVersion']) is int and record['schemaVersion'] == 1
            and record['sourceSha'] == source and record['platformRef'] == platform
            and record['platform'] == 'linux/arm64', 'PENPOT_RELEASE_ARTIFACT')
    actual = image_map(record['images'], PENPOT_REPOSITORIES)
    require(actual == image_map(expected_images, PENPOT_REPOSITORIES), 'PENPOT_RELEASE_ARTIFACT')
    return actual


def archive_hash(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def publish(archive, metadata, source, platform):
    require(type(source) is str and SHA.fullmatch(source) and type(platform) is str and SHA.fullmatch(platform),
            'PENPOT_BUILD_IDENTITY')
    require(type(metadata) is dict and set(metadata) == {
        'schemaVersion', 'sourceSha', 'platformRef', 'platform', 'archiveSha256'}, 'PENPOT_BUILD_ARTIFACT')
    require(type(metadata['schemaVersion']) is int and metadata['schemaVersion'] == 1
            and metadata['sourceSha'] == source and metadata['platformRef'] == platform
            and metadata['platform'] == 'linux/arm64' and type(metadata['archiveSha256']) is str
            and HASH.fullmatch(metadata['archiveSha256']), 'PENPOT_BUILD_ARTIFACT')
    path = Path(archive)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size > 0
            and archive_hash(path) == metadata['archiveSha256'], 'PENPOT_BUILD_CHECKSUM')
    docker('load', '--input', str(path), timeout=600)
    tags = {role: repository + ':sha-' + source for role, repository in PENPOT_REPOSITORIES.items()}
    # Validate the complete set before the first push; a mixed release has no output.
    for role, tag in tags.items():
        value = inspect('image', tag)
        config = value.get('Config') or {}
        labels = config.get('Labels') or {}
        require(value.get('Architecture') == 'arm64' and value.get('Os') == 'linux'
                and labels.get('org.opencontainers.image.source') == 'https://github.com/TheDemonTuan/penpot'
                and labels.get('org.opencontainers.image.revision') == source
                and config.get('User', '').split(':')[0] not in ('', '0', 'root'), 'PENPOT_IMAGE_REVISION')
    images = {}
    for role, tag in tags.items():
        docker('push', tag, timeout=600)
        repository = PENPOT_REPOSITORIES[role]
        refs = inspect('image', tag).get('RepoDigests') or []
        matches = {ref for ref in refs if type(ref) is str and ref.startswith(repository + '@sha256:')}
        require(len(matches) == 1, 'PENPOT_PUBLISHED_DIGEST')
        images[role] = matches.pop()
        require(HASH.fullmatch(images[role].removeprefix(repository + '@sha256:')) is not None,
                'PENPOT_PUBLISHED_DIGEST')
    image_map(images, PENPOT_REPOSITORIES)
    # Create every package before anonymous checks: new GHCR packages may be private.
    for ref in images.values():
        anonymous_image(ref)
    return {'schemaVersion': 1, 'sourceSha': source, 'platformRef': platform,
            'platform': 'linux/arm64', 'images': images}
