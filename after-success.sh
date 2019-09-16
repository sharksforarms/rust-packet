#!/usr/bin/env bash

# Clone the repository
REMOTE_URL="$(git config --get remote.origin.url)";
cd ${TRAVIS_BUILD_DIR}/.. && \
git clone ${REMOTE_URL} "${TRAVIS_REPO_SLUG}-bench" && \
cd  "${TRAVIS_REPO_SLUG}-bench" && \

# Bench master
git checkout master && \
cargo bench --bench benchmark -- --noplot --save-baseline before && \

# Bench current branch
git checkout ${TRAVIS_COMMIT} && \
cargo bench --bench benchmark -- --noplot --save-baseline after && \

# Install https://github.com/BurntSushi/critcmp
cargo install critcmp --force && \

# Compare the two generated benches
CRITCMP_OUT="$(critcmp before after)";
printf -v CRITCMP_OUT_ESCP "%q" "$CRITCMP_OUT"

read -d '' DATA_JSON << EOF
{
    "body": "Benchmarks: $(date -u)

\`\`\`text
$CRITCMP_OUT_ESCP
\`\`\`
"
}
EOF

echo "$DATA_JSON" > data.json
cat data.json

# Post github comment with results of benchmark
if [ "${TRAVIS_REPO_SLUG}" == "sharksforarms/rust-packet" ]; then
    COMMENTS_API=""https://api.github.com/repos/${TRAVIS_REPO_SLUG}/issues/${TRAVIS_PULL_REQUEST}/comments"

    # Get existing comment if exists
    COMMENT_URL=$(curl $COMMENTS_API | jq "
    .[] | \
        if (.body | startswith(\"Benchmarks:\")) and (.user.login == \"sharksforarmss\") \
        then \
            .url \
        else \
            error(\"Error: Could not find comment\") \
        end \
        | . \
        ")

    if [ $? -eq 0 ]
    then
        # Update the comment
        curl -vvv -H "Authorization: token ${GITHUB_TOKEN}" -X PATCH \
        "$COMMENT_URL" \
        -d @data.json
    else
        # Create the comment
        curl -vvv -H "Authorization: token ${GITHUB_TOKEN}" -X POST \
        "$COMMENTS_API" \
        -d @data.json
fi
