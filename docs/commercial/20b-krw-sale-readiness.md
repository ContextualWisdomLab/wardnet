# Compatibility notice: commercial readiness authority moved

This historical path is retained only because protected-main buyer-evidence manifests and external links may still reference `docs/commercial/20b-krw-sale-readiness.md`. The filename is misleading: the runtime contract it historically described is **2B KRW**, not 20B KRW, and it is unrelated to Wardnet's USD 20 billion software-quality ambition.

Canonical authorities are now separated:

- [2B KRW Customer Contract Readiness](./2b-krw-customer-contract-readiness.md) defines the existing `annual_contract_value_krw` / `target_sale_value_krw` compatibility predicate.
- [USD 20 Billion Product Quality Bar](./usd-20b-product-quality-bar.md) defines the software-quality and buyer-evidence ambition.

This compatibility filename **must not be used as numeric authority** for either concept. Keeping it temporarily avoids breaking the currently published evidence-manifest document path while the runtime API still exposes that path. A later versioned API/document-manifest migration may remove this shim after consumers have a compatibility window.

Do not infer a 20B KRW customer threshold from this filename and do not encode the USD 20 billion product-quality bar into tenant pricing, billing, license, or accounting fields.
