import os

from troposphere import AWS_REGION, GetAtt, If, Join, Ref

from .assets import (
    assets_bucket,
    assets_cloudfront_domain,
    assets_custom_domain_condition,
    assets_use_cloudfront_condition,
    distribution,
    private_assets_bucket
)
from .cache import (
    cache_cluster,
    cache_condition,
    cache_engine,
    using_redis_condition
)
from .common import secret_key
from .database import (
    db_condition,
    db_engine,
    db_instance,
    db_name,
    db_password,
    db_user
)
from .domain import domain_name, domain_name_alternates

if os.environ.get('USE_GOVCLOUD') != 'on':
    # not supported by GovCloud, so add it only if it was created (and in this
    # case we want to avoid importing if it's not needed)
    from .search import es_condition, es_domain
else:
    es_domain = None

environment_variables = [
    ("AWS_REGION", Ref(AWS_REGION)),
    ("AWS_STORAGE_BUCKET_NAME", Ref(assets_bucket)),
    ("AWS_PRIVATE_STORAGE_BUCKET_NAME", Ref(private_assets_bucket)),
    ("DOMAIN_NAME", domain_name),
    ("ALTERNATE_DOMAIN_NAMES", Join(',', domain_name_alternates)),
    ("SECRET_KEY", secret_key),
    ("DATABASE_URL", If(
        db_condition,
        Join("", [
            Ref(db_engine),
            "://",
            Ref(db_user),
            ":",
            Ref(db_password),
            "@",
            GetAtt(db_instance, 'Endpoint.Address'),
            ":",
            GetAtt(db_instance, 'Endpoint.Port'),
            "/",
            Ref(db_name),
        ]),
        "",  # defaults to empty string if no DB was created
    )),
    ("CACHE_URL", If(
        cache_condition,
        Join("", [
            Ref(cache_engine),
            "://",
            If(
                using_redis_condition,
                GetAtt(cache_cluster, 'RedisEndpoint.Address'),
                GetAtt(cache_cluster, 'ConfigurationEndpoint.Address')
            ),
            ":",
            If(
                using_redis_condition,
                GetAtt(cache_cluster, 'RedisEndpoint.Port'),
                GetAtt(cache_cluster, 'ConfigurationEndpoint.Port')
            ),
        ]),
        "",  # defaults to empty string if no cache was created
    )),
]

if distribution:
    # not supported by GovCloud, so add it only if it was created
    environment_variables.append(
        ("CDN_DOMAIN_NAME", If(
            assets_use_cloudfront_condition,
            If(
                # use the custom domain passed into the stack, otherwise fallback to the default domain
                assets_custom_domain_condition,
                Ref(assets_cloudfront_domain),
                GetAtt(distribution, "DomainName"),
            ),
            "",
        )),
    )

if es_domain:
    # not supported by GovCloud, so add it only if it was created
    environment_variables += [
        ("ELASTICSEARCH_ENDPOINT", If(es_condition, GetAtt(es_domain, "DomainEndpoint"), "")),
        ("ELASTICSEARCH_PORT", If(es_condition, "443", "")),
        ("ELASTICSEARCH_USE_SSL", If(es_condition, "on", "")),
        ("ELASTICSEARCH_VERIFY_CERTS", If(es_condition, "on", "")),
    ]
