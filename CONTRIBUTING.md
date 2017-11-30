# Contributing

Thank you for your interest in contributing to security-headers!

## Raise an Issue First

If you find any problems or have things you wish were included, please look for an existing issue on GitHub first. It is possible someone is already looking into it, so it's the best place to collaborate with people. Even just leaving a thumbs-up emoji helps to indicate community interest in a particular issue or feature request.

If you don't find an issue, please make one. The last thing you want is to have a pull request rejected as it's a duplicate or doesn't fit the direction of this project.

In short: talk to someone first.

## Development

Irrespective of which commit you check out, the project must always:

 * Have no syntax errors (PHP 7.0 baseline).
 * Pass all unit tests perfectly.
 * Be in conformance with PSR-2 (coding style).
 * Have useful, well-written documentation with good spelling and grammar.
 * Contain descriptive, professional commit messages.

To help achieve this high standard of quality, there are several tools you should run _before_ you commit.

To run the unit tests, execute this in the root:

	vendor/bin/phpunit

To check code against the PSR-2 standard, you can run PHP Code Sniffer:

	vendor/bin/phpcs

**Tip:** If you see errors when running phpcs, replace `phpcs` with `phpcbf` which can fix some of the reported issues automatically.

Aim to limit lines to 80 characters long if possible.

## Communication

Documentation and commit messages MUST be written in American English, with good spelling and grammar.

### PHP Documentation

Documentation MUST follow the [phpDocumentor DocBlock](https://docs.phpdoc.org/guides/docblocks.html) format.

You MUST include a 1 line summary of a function or class, and MAY include a longer, multi-line description. The summary, description, and tags MUST be separated by a blank DocBlock line.

Tags MUST be ordered `@param`, `@throws`, and `@return`, which logically follows how the function executes; inspects parameters, throws exceptions if assertions fail, and finally, returns a value.

This is an example of a valid DocBlock:

```
/**
 * Teleport the user in space and time.
 *
 * This function takes a DateTime and a pair of coordinates, and teleports
 * the calling user to the destination time and place. The class MUST have
 * been given a power source of at-least 1.21 gigawatts, else this function
 * will fail.
 *
 * @param  \DateTime $destination Destination Day and Time
 * @param  float     $longitude   Destination Longitude
 * @param  float     $latitude    Destination Latitude
 * @throws \RuntimeException Flux capacitor requires 1.21 gigawatts of power.
 * @return void
 */
```

### Commits

Commits MUST be atomic, that is, they serve a single purpose. For example, don't fix a bug and introduce a new feature in one commit. Create two commits.

Commits SHOULD be PGP signed with a public, valid, non-expired key. The signing public key MUST be uploaded to GitHub so a "verified" badge will show. Your key SHOULD be on keybase.io with your GitHub account linked and verified.

### Commit Messages

Commit messages MUST follow the [Seven Rules of a great Git commit message](https://chris.beams.io/posts/git-commit/#seven-rules):

 1. Separate subject from body with a blank line.
 2. Limit the subject line to 50 characters.
 3. Capitalize the subject line.
 4. Do not end the subject line with a period.
 5. Use the imperative mood in the subject line.
 6. Wrap the body at 72 characters.
 7. Use the body to explain what and why vs. how.

It's very important your commit message is clear, detailed, and useful to someone reading it or to yourself 6 months from now.

You MUST not use emojis, icons, or ASCII art in commit messages as they may not display correctly on some people's monitors, operating systems, terminals, text editors, or web browsers.

## Code of Conduct

Profanity, personal attacks, and derogatory comments in commit messages, pull request descriptions, comments, documentation, notes, and strings will not be tolerated.

 * Be civil -- don't say anything you wouldn't to someone you respect.
 * Think before you type -- remember there's a human being on the receiving side of your message.
 * Wait until tomorrow to post that angry rant you just wrote. You aren't likely to change minds or behavior by being unapproachable.
