cmake_minimum_required(VERSION 3.21)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(SilentRunnerCTest LANGUAGES NONE)
    include(CTest)
endif()


if(NOT BUILD_TESTING)
    return()
endif()

if(TARGET SilentRunner)
    # Integrated mode: test the executable produced by the current build.
    # The path is resolved during generation; the EXE need not exist yet.
    # Running ctest does not build the executable.
    set(SILENTRUNNER_EXE "$<TARGET_FILE:SilentRunner>")
else()
    # Standalone mode: test an existing executable without compiling sources.
    if(NOT DEFINED SILENTRUNNER_EXE OR SILENTRUNNER_EXE STREQUAL "")
        message(FATAL_ERROR
            "SILENTRUNNER_EXE is required.\n"
            "Configure from the test suite directory with:\n"
            "  cmake -S . -B build -DSILENTRUNNER_EXE=C:/path/to/SilentRunner.exe"
        )
    endif()

    cmake_path(
        ABSOLUTE_PATH SILENTRUNNER_EXE
        NORMALIZE
        OUTPUT_VARIABLE SILENTRUNNER_EXE
    )

    if(NOT EXISTS "${SILENTRUNNER_EXE}" OR IS_DIRECTORY "${SILENTRUNNER_EXE}")
        message(FATAL_ERROR
            "SilentRunner executable is not an existing file: ${SILENTRUNNER_EXE}"
        )
    endif()
endif()

set(SR_TESTS_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/tests")
set(SR_TESTS_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/tests")

function(sr_add_script_test name script)
    add_test(
        NAME "${name}"
        COMMAND
            "${CMAKE_COMMAND}"
            "-DSILENTRUNNER_EXE=${SILENTRUNNER_EXE}"
            "-DSR_TESTS_SOURCE_DIR=${SR_TESTS_SOURCE_DIR}"
            "-DSR_TESTS_BINARY_DIR=${SR_TESTS_BINARY_DIR}"
            "-DSR_TEST_NAME=${name}"
            -P "${SR_TESTS_SOURCE_DIR}/${script}"
    )

    string(REGEX REPLACE "\\..*$" "" test_label "${name}")
    set_tests_properties(
        "${name}"
        PROPERTIES
            TIMEOUT 15
            LABELS "${test_label}"
    )
endfunction()

# parser
sr_add_script_test(parser.unknown-argument                        parser/unknown-argument.cmake)
sr_add_script_test(parser.duplicate-debug                         parser/duplicate-debug.cmake)
sr_add_script_test(parser.missing-timeout-value                   parser/missing-timeout-value.cmake)
sr_add_script_test(parser.invalid-timeout-text                    parser/invalid-timeout-text.cmake)
sr_add_script_test(parser.timeout-overflow                        parser/timeout-overflow.cmake)
sr_add_script_test(parser.timeout-equals-form                     parser/timeout-equals-form.cmake)
sr_add_script_test(parser.case-insensitive-option                 parser/case-insensitive-option.cmake)
sr_add_script_test(parser.utf8-alias                              parser/utf8-alias.cmake)
sr_add_script_test(parser.utf8-alias-duplicate                    parser/utf8-alias-duplicate.cmake)
sr_add_script_test(parser.timeout-zero                            parser/timeout-zero.cmake)
sr_add_script_test(parser.timeout-one-accepted                     parser/timeout-one-accepted.cmake)
sr_add_script_test(parser.timeout-max                             parser/timeout-max.cmake)
sr_add_script_test(parser.timeout-negative                        parser/timeout-negative.cmake)
sr_add_script_test(parser.duplicate-timeout                       parser/duplicate-timeout.cmake)
sr_add_script_test(parser.verbose                                 parser/verbose.cmake)
sr_add_script_test(parser.duplicate-verbose                       parser/duplicate-verbose.cmake)
sr_add_script_test(parser.inherit-stdin-accepted                  parser/inherit-stdin-accepted.cmake)
sr_add_script_test(parser.duplicate-cwd                           parser/duplicate-cwd.cmake)
sr_add_script_test(parser.duplicate-id-base                       parser/duplicate-id-base.cmake)
sr_add_script_test(parser.invalid-emit-mode                       parser/invalid-emit-mode.cmake)
sr_add_script_test(parser.invalid-keep-log-mode                   parser/invalid-keep-log-mode.cmake)
sr_add_script_test(parser.invalid-id-suffix-mode                  parser/invalid-id-suffix-mode.cmake)
sr_add_script_test(parser.id-base-equals-form                     parser/id-base-equals-form.cmake)
sr_add_script_test(parser.option-after-child-is-child-argument    parser/option-after-child-is-child-argument.cmake)
sr_add_script_test(parser.stdout-event-framing-values             parser/stdout-event-framing-values.cmake)
sr_add_script_test(parser.stderr-child-event-framing-values       parser/stderr-child-event-framing-values.cmake)
sr_add_script_test(parser.event-framing-invalid                   parser/event-framing-invalid.cmake)
sr_add_script_test(parser.stdout-newline-max-boundaries           parser/stdout-newline-max-boundaries.cmake)
sr_add_script_test(parser.stderr-child-newline-max-boundaries     parser/stderr-child-newline-max-boundaries.cmake)
sr_add_script_test(parser.newline-max-requires-framing            parser/newline-max-requires-framing.cmake)
sr_add_script_test(parser.new-output-options-missing-duplicate    parser/new-output-options-missing-duplicate.cmake)
sr_add_script_test(parser.jsonl-payload-representation-values       parser/jsonl-payload-presentation-values.cmake)
sr_add_script_test(parser.jsonl-payload-representation-invalid      parser/jsonl-payload-presentation-invalid.cmake)


# id
sr_add_script_test(id.valid-prefix               id/valid-prefix.cmake)
sr_add_script_test(id.invalid-prefix             id/invalid-prefix.cmake)
sr_add_script_test(id.suffix.timestamp           id/suffix-timestamp.cmake)
sr_add_script_test(id.suffix.pid                 id/suffix-pid.cmake)
sr_add_script_test(id.suffix.timestamp-pid       id/suffix-timestamp-pid.cmake)
sr_add_script_test(id.suffix.pid-timestamp       id/suffix-pid-timestamp.cmake)
sr_add_script_test(id.valid-base                 id/valid-base.cmake)
sr_add_script_test(id.invalid-base               id/invalid-base.cmake)
sr_add_script_test(id.invalid-prefix-space       id/invalid-prefix-space.cmake)
sr_add_script_test(id.invalid-base-slash         id/invalid-base-slash.cmake)
sr_add_script_test(id.suffix.case-insensitive    id/suffix-case-insensitive.cmake)
sr_add_script_test(id.default-timestamp-pid      id/default-timestamp-pid.cmake)
sr_add_script_test(id.base-without-suffix        id/base-without-suffix.cmake)
sr_add_script_test(id.prefix-without-suffix      id/prefix-without-suffix.cmake)
sr_add_script_test(id.prefix-and-base            id/prefix-and-base.cmake)

# path
sr_add_script_test(path.probe-dir.invalid-character                       path/probe-dir-invalid-character.cmake)
sr_add_script_test(path.run-on-success.invalid-character                  path/run-on-success-invalid-character.cmake)
sr_add_script_test(path.run-on-failure.invalid-character                  path/run-on-failure-invalid-character.cmake)
sr_add_script_test(path.stdout-dir.invalid-character                      path/stdout-dir-invalid-character.cmake)
sr_add_script_test(path.stdout-dir-jsonl.invalid-character                path/stdout-dir-jsonl-invalid-character.cmake)
sr_add_script_test(path.stderr-dir.invalid-character                      path/stderr-dir-invalid-character.cmake)
sr_add_script_test(path.stderr-dir-jsonl.invalid-character                path/stderr-dir-jsonl-invalid-character.cmake)
sr_add_script_test(path.stderr-dir-child.invalid-character                path/stderr-dir-child-invalid-character.cmake)
sr_add_script_test(path.stderr-dir-child-jsonl.invalid-character          path/stderr-dir-child-jsonl-invalid-character.cmake)
sr_add_script_test(path.stderr-dir-sr.invalid-character                   path/stderr-dir-sr-invalid-character.cmake)
sr_add_script_test(path.stderr-dir-sr-jsonl.invalid-character             path/stderr-dir-sr-jsonl-invalid-character.cmake)
sr_add_script_test(path.stderr-dir-incl-stdout.invalid-character          path/stderr-dir-incl-stdout-invalid-character.cmake)
sr_add_script_test(path.stderr-dir-incl-stdout-jsonl.invalid-character    path/stderr-dir-incl-stdout-jsonl-invalid-character.cmake)
sr_add_script_test(path.stdout-dir.leading-whitespace                     path/stdout-dir-leading-whitespace.cmake)
sr_add_script_test(path.stdout-dir.trailing-whitespace                    path/stdout-dir-trailing-whitespace.cmake)
sr_add_script_test(path.stdout-dir.double-quote                           path/stdout-dir-double-quote.cmake)
sr_add_script_test(path.stdout-dir.less-than                              path/stdout-dir-less-than.cmake)
sr_add_script_test(path.stdout-dir.greater-than                           path/stdout-dir-greater-than.cmake)
sr_add_script_test(path.stdout-dir.pipe                                   path/stdout-dir-pipe.cmake)
sr_add_script_test(path.stdout-dir.asterisk                               path/stdout-dir-asterisk.cmake)

# cwd
sr_add_script_test(cwd.invalid-character                      cwd/invalid-character.cmake)
sr_add_script_test(cwd.create-relative                        cwd/create-relative.cmake)
sr_add_script_test(cwd.existing-relative                      cwd/existing-relative.cmake)
sr_add_script_test(cwd.existing-absolute                      cwd/existing-absolute.cmake)
sr_add_script_test(cwd.points-to-file                         cwd/points-to-file.cmake)
sr_add_script_test(cwd.equals-form                            cwd/equals-form.cmake)
sr_add_script_test(cwd.with-spaces                            cwd/with-spaces.cmake)
sr_add_script_test(cwd.does-not-change-log-resolution-base    cwd/log-resolution-base.cmake)

# hooks
sr_add_script_test(hooks.success-relative                          hooks/success-relative.cmake)
sr_add_script_test(hooks.failure-relative                          hooks/failure-relative.cmake)
sr_add_script_test(hooks.missing                                   hooks/missing.cmake)
sr_add_script_test(hooks.success-absolute                          hooks/success-absolute.cmake)
sr_add_script_test(hooks.failure-absolute                          hooks/failure-absolute.cmake)
sr_add_script_test(hooks.success-not-run-on-failure                hooks/success-not-run-on-failure.cmake)
sr_add_script_test(hooks.failure-not-run-on-success                hooks/failure-not-run-on-success.cmake)
sr_add_script_test(hooks.cwd-applied                               hooks/cwd-applied.cmake)
sr_add_script_test(hooks.relative-resolution-independent-of-cwd    hooks/relative-resolution-independent-of-cwd.cmake)
sr_add_script_test(hooks.environment-success                       hooks/environment-success.cmake)
sr_add_script_test(hooks.environment-failure                       hooks/environment-failure.cmake)
sr_add_script_test(hooks.environment-retained-log                  hooks/environment-retained-log.cmake)
sr_add_script_test(hooks.environment-removed-log-empty             hooks/environment-removed-log-empty.cmake)
sr_add_script_test(hooks.environment-overrides-inherited             hooks/environment-overrides-inherited.cmake)


sr_add_script_test(hooks.nonzero-exit                            hooks/nonzero-exit.cmake)
sr_add_script_test(hooks.detached-nested-no-diagnostic-channel      hooks/detached-nested-no-diagnostic-channel.cmake)

# command
sr_add_script_test(command.script-no-args                  command/script-no-args.cmake)
sr_add_script_test(command.script-argument-with-space      command/script-argument-with-space.cmake)
sr_add_script_test(command.child-help-is-child-argument    command/child-help-is-child-argument.cmake)
sr_add_script_test(command.raw-c                           command/raw-c.cmake)
sr_add_script_test(command.raw-slash-c                     command/raw-slash-c.cmake)
sr_add_script_test(command.raw-missing                     command/raw-missing.cmake)
sr_add_script_test(command.raw-multiple-argv               command/raw-multiple-argv.cmake)
sr_add_script_test(command.script-multiple-arguments       command/script-multiple-arguments.cmake)
sr_add_script_test(command.script-path-with-spaces         command/script-path-with-spaces.cmake)
sr_add_script_test(command.raw-chaining                    command/raw-chaining.cmake)
sr_add_script_test(command.raw-pipe                        command/raw-pipe.cmake)
sr_add_script_test(command.raw-redirection                 command/raw-redirection.cmake)
sr_add_script_test(command.inherit-stdin-content                     command/inherit-stdin-content.cmake)


# utf8
sr_add_script_test(utf8.codepage-65001    utf8/codepage-65001.cmake)

# timeout
sr_add_script_test(timeout.exit-124                                   timeout/exit-124.cmake)
sr_add_script_test(timeout.completes-before-timeout                   timeout/completes-before-timeout.cmake)
sr_add_script_test(timeout.failure-emission-preserves-early-stdout    timeout/failure-emission-preserves-early-stdout.cmake)
sr_add_script_test(timeout.failure-retention                          timeout/failure-retention.cmake)
sr_add_script_test(timeout.failure-hook                               timeout/failure-hook.cmake)

# emit
sr_add_script_test(emit.stdout.never.success                           emit/stdout-never-success.cmake)
sr_add_script_test(emit.stdout.stream.success                          emit/stdout-stream-success.cmake)
sr_add_script_test(emit.stdout.end.success                             emit/stdout-end-success.cmake)
sr_add_script_test(emit.stdout.success.success                         emit/stdout-success-success.cmake)
sr_add_script_test(emit.stdout.success.failure                         emit/stdout-success-failure.cmake)
sr_add_script_test(emit.stdout.failure.success                         emit/stdout-failure-success.cmake)
sr_add_script_test(emit.stdout.failure.failure                         emit/stdout-failure-failure.cmake)
sr_add_script_test(emit.stderr-source-conflict                         emit/stderr-source-conflict.cmake)
sr_add_script_test(emit.stderr.combined.never.success                  emit/stderr-combined-never-success.cmake)
sr_add_script_test(emit.stderr.combined.stream.success                 emit/stderr-combined-stream-success.cmake)
sr_add_script_test(emit.stderr.combined.end.success                    emit/stderr-combined-end-success.cmake)
sr_add_script_test(emit.stderr.combined.success.success                emit/stderr-combined-success-success.cmake)
sr_add_script_test(emit.stderr.combined.success.failure                emit/stderr-combined-success-failure.cmake)
sr_add_script_test(emit.stderr.combined.failure.success                emit/stderr-combined-failure-success.cmake)
sr_add_script_test(emit.stderr.combined.failure.failure                emit/stderr-combined-failure-failure.cmake)
sr_add_script_test(emit.stderr.child.never.success                     emit/stderr-child-never-success.cmake)
sr_add_script_test(emit.stderr.child.stream.success                    emit/stderr-child-stream-success.cmake)
sr_add_script_test(emit.stderr.child.end.success                       emit/stderr-child-end-success.cmake)
sr_add_script_test(emit.stderr.child.success.success                   emit/stderr-child-success-success.cmake)
sr_add_script_test(emit.stderr.child.success.failure                   emit/stderr-child-success-failure.cmake)
sr_add_script_test(emit.stderr.child.failure.success                   emit/stderr-child-failure-success.cmake)
sr_add_script_test(emit.stderr.child.failure.failure                   emit/stderr-child-failure-failure.cmake)
sr_add_script_test(emit.stderr.sr.never.success                        emit/stderr-sr-never-success.cmake)
sr_add_script_test(emit.stderr.sr.stream.success                       emit/stderr-sr-stream-success.cmake)
sr_add_script_test(emit.stderr.sr.end.success                          emit/stderr-sr-end-success.cmake)
sr_add_script_test(emit.stderr.sr.success.success                      emit/stderr-sr-success-success.cmake)
sr_add_script_test(emit.stderr.sr.success.failure                      emit/stderr-sr-success-failure.cmake)
sr_add_script_test(emit.stderr.sr.failure.success                      emit/stderr-sr-failure-success.cmake)
sr_add_script_test(emit.stderr.sr.failure.failure                      emit/stderr-sr-failure-failure.cmake)
sr_add_script_test(emit.stderr.incl-stdout.never.success               emit/stderr-incl-stdout-never-success.cmake)
sr_add_script_test(emit.stderr.incl-stdout.stream.success              emit/stderr-incl-stdout-stream-success.cmake)
sr_add_script_test(emit.stderr.incl-stdout.end.success                 emit/stderr-incl-stdout-end-success.cmake)
sr_add_script_test(emit.stderr.incl-stdout.success.success             emit/stderr-incl-stdout-success-success.cmake)
sr_add_script_test(emit.stderr.incl-stdout.success.failure             emit/stderr-incl-stdout-success-failure.cmake)
sr_add_script_test(emit.stderr.incl-stdout.failure.success             emit/stderr-incl-stdout-failure-success.cmake)
sr_add_script_test(emit.stderr.incl-stdout.failure.failure             emit/stderr-incl-stdout-failure-failure.cmake)
sr_add_script_test(emit.stderr-source-conflict.combined-sr             emit/stderr-source-conflict-combined-sr.cmake)
sr_add_script_test(emit.stderr-source-conflict.combined-incl-stdout    emit/stderr-source-conflict-combined-incl-stdout.cmake)
sr_add_script_test(emit.stderr-source-conflict.combined-child           emit/stderr-source-conflict-combined-child.cmake)
sr_add_script_test(emit.stderr-source-conflict.child-sr                emit/stderr-source-conflict-child-sr.cmake)
sr_add_script_test(emit.stderr-source-conflict.child-incl-stdout       emit/stderr-source-conflict-child-incl-stdout.cmake)
sr_add_script_test(emit.stderr-source-conflict.sr-incl-stdout          emit/stderr-source-conflict-sr-incl-stdout.cmake)
sr_add_script_test(emit.lf-event-headers                       emit/lf-event-headers.cmake)

# framing
sr_add_script_test(framing.stdout-lf-events                  framing/stdout-lf-events.cmake)
sr_add_script_test(framing.stderr-child-lf-events            framing/stderr-child-lf-events.cmake)
sr_add_script_test(framing.crlf-exact-delimiter              framing/crlf-exact-delimiter.cmake)
sr_add_script_test(framing.crlf-threshold-extra-byte         framing/crlf-threshold-extra-byte.cmake)
sr_add_script_test(framing.crlf-threshold-non-lf             framing/crlf-threshold-non-lf.cmake)
sr_add_script_test(framing.eof-tail                          framing/eof-tail.cmake)
sr_add_script_test(framing.default-newline-threshold         framing/default-newline-threshold.cmake)
sr_add_script_test(framing.independent-stream-settings       framing/independent-stream-settings.cmake)
sr_add_script_test(framing.utf8-split-at-byte-threshold      framing/utf8-split-at-byte-threshold.cmake)

# replay
sr_add_script_test(replay.stdout-txt-end                      replay/stdout-txt-end.cmake)
sr_add_script_test(replay.stdout-jsonl-end                    replay/stdout-jsonl-end.cmake)
sr_add_script_test(replay.jsonl-text-trailing-comma             replay/jsonl-text-trailing-comma.cmake)
sr_add_script_test(replay.jsonl-text-escaping-utf8              replay/jsonl-text-escaping-utf8.cmake)
sr_add_script_test(replay.jsonl-base64-end                      replay/jsonl-base64-end.cmake)
sr_add_script_test(replay.jsonl-dual-payload-end                replay/jsonl-dual-payload-end.cmake)
sr_add_script_test(replay.stdout-txt-success                  replay/stdout-txt-success.cmake)
sr_add_script_test(replay.stderr-sr-txt-end                   replay/stderr-sr-txt-end.cmake)
sr_add_script_test(replay.stderr-incl-stdout-jsonl-end         replay/stderr-incl-stdout-jsonl-end.cmake)
sr_add_script_test(replay.stderr-sr-jsonl-failure              replay/stderr-sr-jsonl-failure.cmake)
sr_add_script_test(replay.stdout-txt-lf-events                 replay/stdout-txt-lf-events.cmake)
sr_add_script_test(replay.stderr-incl-stdout-txt-framing       replay/stderr-incl-stdout-txt-framing.cmake)
sr_add_script_test(replay.timeline-lf-events                   replay/timeline-lf-events.cmake)
sr_add_script_test(replay.txt-event-without-final-newline      replay/txt-event-without-final-newline.cmake)
sr_add_script_test(replay.txt-header-like-child-payload        replay/txt-header-like-child-payload.cmake)
sr_add_script_test(replay.txt-large-event                      replay/txt-large-event.cmake)
sr_add_script_test(replay.jsonl-preferred-over-txt             replay/jsonl-preferred-over-txt.cmake)
sr_add_script_test(replay.unrelated-log-keeps-timeline          replay/unrelated-log-keeps-timeline.cmake)
sr_add_script_test(replay.mixed-stdout-txt-stderr-jsonl         replay/mixed-stdout-txt-stderr-jsonl.cmake)
sr_add_script_test(replay.before-retention-removal              replay/before-retention-removal.cmake)
sr_add_script_test(replay.persistent-result-gating              replay/persistent-result-gating.cmake)
sr_add_script_test(replay.stderr-child-txt-end                  replay/stderr-child-txt-end.cmake)
sr_add_script_test(replay.stderr-combined-jsonl-end             replay/stderr-combined-jsonl-end.cmake)




# logging
sr_add_script_test(logging.stdout-txt                          logging/stdout-txt.cmake)
sr_add_script_test(logging.lf-event-headers                    logging/lf-event-headers.cmake)


sr_add_script_test(logging.stdout-jsonl                        logging/stdout-jsonl.cmake)
sr_add_script_test(logging.stderr-child-txt                    logging/stderr-child-txt.cmake)
sr_add_script_test(logging.stdout-txt.failure                  logging/stdout-txt-failure.cmake)
sr_add_script_test(logging.stdout-jsonl.failure                logging/stdout-jsonl-failure.cmake)
sr_add_script_test(logging.stderr-txt.success                  logging/stderr-txt-success.cmake)
sr_add_script_test(logging.stderr-txt.failure                  logging/stderr-txt-failure.cmake)
sr_add_script_test(logging.stderr-jsonl.success                logging/stderr-jsonl-success.cmake)
sr_add_script_test(logging.stderr-jsonl.failure                logging/stderr-jsonl-failure.cmake)
sr_add_script_test(logging.stderr-child-txt.success            logging/stderr-child-txt-success.cmake)
sr_add_script_test(logging.stderr-child-jsonl.success          logging/stderr-child-jsonl-success.cmake)
sr_add_script_test(logging.stderr-child-jsonl.failure          logging/stderr-child-jsonl-failure.cmake)
sr_add_script_test(logging.stderr-sr-txt.success               logging/stderr-sr-txt-success.cmake)
sr_add_script_test(logging.stderr-sr-txt.failure               logging/stderr-sr-txt-failure.cmake)
sr_add_script_test(logging.stderr-sr-jsonl.success             logging/stderr-sr-jsonl-success.cmake)
sr_add_script_test(logging.stderr-sr-jsonl.failure             logging/stderr-sr-jsonl-failure.cmake)
sr_add_script_test(logging.verbose-final-summary-jsonl          logging/verbose-final-summary-jsonl.cmake)
sr_add_script_test(logging.jsonl-representation-base64            logging/jsonl-presentation-base64.cmake)
sr_add_script_test(logging.jsonl-representation-text-and-base64   logging/jsonl-presentation-text-and-base64.cmake)
sr_add_script_test(logging.jsonl-invalid-utf8-fallback          logging/jsonl-invalid-utf8-fallback.cmake)
sr_add_script_test(logging.jsonl-event-identity                      logging/jsonl-event-identity.cmake)

sr_add_script_test(logging.stderr-incl-stdout-txt.success      logging/stderr-incl-stdout-txt-success.cmake)
sr_add_script_test(logging.stderr-incl-stdout-txt.failure      logging/stderr-incl-stdout-txt-failure.cmake)
sr_add_script_test(logging.stderr-incl-stdout-jsonl.success    logging/stderr-incl-stdout-jsonl-success.cmake)
sr_add_script_test(logging.stderr-incl-stdout-jsonl.failure    logging/stderr-incl-stdout-jsonl-failure.cmake)
sr_add_script_test(logging.probe-dir                           logging/probe-dir.cmake)
sr_add_script_test(logging.creates-nested-directory            logging/creates-nested-directory.cmake)
sr_add_script_test(logging.all-destinations-parallel           logging/all-destinations-parallel.cmake)
sr_add_script_test(logging.collision.stdout-txt.running   logging/collision-stdout-txt-running.cmake)
sr_add_script_test(logging.collision.stdout-txt.success   logging/collision-stdout-txt-success.cmake)
sr_add_script_test(logging.collision.stdout-txt.failure   logging/collision-stdout-txt-failure.cmake)
sr_add_script_test(logging.collision.stdout-jsonl.success logging/collision-stdout-jsonl-success.cmake)
sr_add_script_test(logging.stdout-dir-points-to-file           logging/stdout-dir-points-to-file.cmake)

# retention
sr_add_script_test(retention.stdout.success-on-success                retention/stdout-success-on-success.cmake)
sr_add_script_test(retention.stdout.success-on-failure                retention/stdout-success-on-failure.cmake)
sr_add_script_test(retention.stdout.failure-on-success                retention/stdout-failure-on-success.cmake)
sr_add_script_test(retention.stdout.failure-on-failure                retention/stdout-failure-on-failure.cmake)
sr_add_script_test(retention.stdout.always-on-success                 retention/stdout-always-on-success.cmake)
sr_add_script_test(retention.stdout.always-on-failure                 retention/stdout-always-on-failure.cmake)
sr_add_script_test(retention.stderr.always-on-success                 retention/stderr-always-on-success.cmake)
sr_add_script_test(retention.stderr.always-on-failure                 retention/stderr-always-on-failure.cmake)
sr_add_script_test(retention.stderr.success-on-success                retention/stderr-success-on-success.cmake)
sr_add_script_test(retention.stderr.success-on-failure                retention/stderr-success-on-failure.cmake)
sr_add_script_test(retention.stderr.failure-on-success                retention/stderr-failure-on-success.cmake)
sr_add_script_test(retention.stderr.failure-on-failure                retention/stderr-failure-on-failure.cmake)
sr_add_script_test(retention.stderr-child.always-on-success           retention/stderr-child-always-on-success.cmake)
sr_add_script_test(retention.stderr-child.always-on-failure           retention/stderr-child-always-on-failure.cmake)
sr_add_script_test(retention.stderr-child.success-on-success          retention/stderr-child-success-on-success.cmake)
sr_add_script_test(retention.stderr-child.success-on-failure          retention/stderr-child-success-on-failure.cmake)
sr_add_script_test(retention.stderr-child.failure-on-success          retention/stderr-child-failure-on-success.cmake)
sr_add_script_test(retention.stderr-child.failure-on-failure          retention/stderr-child-failure-on-failure.cmake)
sr_add_script_test(retention.stderr-sr.always-on-success              retention/stderr-sr-always-on-success.cmake)
sr_add_script_test(retention.stderr-sr.always-on-failure              retention/stderr-sr-always-on-failure.cmake)
sr_add_script_test(retention.stderr-sr.success-on-success             retention/stderr-sr-success-on-success.cmake)
sr_add_script_test(retention.stderr-sr.success-on-failure             retention/stderr-sr-success-on-failure.cmake)
sr_add_script_test(retention.stderr-sr.failure-on-success             retention/stderr-sr-failure-on-success.cmake)
sr_add_script_test(retention.stderr-sr.failure-on-failure             retention/stderr-sr-failure-on-failure.cmake)
sr_add_script_test(retention.stderr-incl-stdout.always-on-success     retention/stderr-incl-stdout-always-on-success.cmake)
sr_add_script_test(retention.stderr-incl-stdout.always-on-failure     retention/stderr-incl-stdout-always-on-failure.cmake)
sr_add_script_test(retention.stderr-incl-stdout.success-on-success    retention/stderr-incl-stdout-success-on-success.cmake)
sr_add_script_test(retention.stderr-incl-stdout.success-on-failure    retention/stderr-incl-stdout-success-on-failure.cmake)
sr_add_script_test(retention.stderr-incl-stdout.failure-on-success    retention/stderr-incl-stdout-failure-on-success.cmake)
sr_add_script_test(retention.stderr-incl-stdout.failure-on-failure    retention/stderr-incl-stdout-failure-on-failure.cmake)
sr_add_script_test(retention.stdout.default-always-on-failure         retention/stdout-default-always-on-failure.cmake)
sr_add_script_test(retention.stdout-jsonl-shares-policy               retention/stdout-jsonl-shares-policy.cmake)

# buffer
sr_add_script_test(buffer.stdout-zero        buffer/stdout-zero.cmake)
sr_add_script_test(buffer.stderr-zero        buffer/stderr-zero.cmake)
sr_add_script_test(buffer.total-zero         buffer/total-zero.cmake)
sr_add_script_test(buffer.stdout-normal      buffer/stdout-normal.cmake)
sr_add_script_test(buffer.stdout-max         buffer/stdout-max.cmake)
sr_add_script_test(buffer.stdout-negative    buffer/stdout-negative.cmake)
sr_add_script_test(buffer.stdout-text        buffer/stdout-text.cmake)
sr_add_script_test(buffer.stdout-overflow    buffer/stdout-overflow.cmake)
sr_add_script_test(buffer.stderr-normal      buffer/stderr-normal.cmake)
sr_add_script_test(buffer.stderr-max         buffer/stderr-max.cmake)
sr_add_script_test(buffer.stderr-negative    buffer/stderr-negative.cmake)
sr_add_script_test(buffer.stderr-text        buffer/stderr-text.cmake)
sr_add_script_test(buffer.stderr-overflow    buffer/stderr-overflow.cmake)
sr_add_script_test(buffer.total-normal       buffer/total-normal.cmake)
sr_add_script_test(buffer.total-max          buffer/total-max.cmake)
sr_add_script_test(buffer.total-negative     buffer/total-negative.cmake)
sr_add_script_test(buffer.total-text         buffer/total-text.cmake)
sr_add_script_test(buffer.total-overflow     buffer/total-overflow.cmake)
sr_add_script_test(buffer.stdout-limit-aborts                 buffer/stdout-limit-aborts.cmake)
sr_add_script_test(buffer.stderr-limit-aborts                 buffer/stderr-limit-aborts.cmake)
sr_add_script_test(buffer.total-limit-aborts                  buffer/total-limit-aborts.cmake)
sr_add_script_test(buffer.persistent-replay-bypasses-limit    buffer/persistent-replay-bypasses-limit.cmake)



# comspec
sr_add_script_test(comspec.fallback-when-missing       comspec/fallback-when-missing.cmake)
sr_add_script_test(comspec.explicit-inherited-value    comspec/explicit-inherited-value.cmake)
sr_add_script_test(comspec.invalid-inherited-value     comspec/invalid-inherited-value.cmake)

# help
sr_add_script_test(help.basic               help/basic.cmake)
sr_add_script_test(help.case-insensitive    help/case-insensitive.cmake)

# defaults
sr_add_script_test(defaults.stdout-stream             defaults/stdout-stream.cmake)
sr_add_script_test(defaults.stderr-combined-stream    defaults/stderr-combined-stream.cmake)
sr_add_script_test(defaults.script-or-exe-mode        defaults/script-or-exe-mode.cmake)

# cross
sr_add_script_test(cross.cwd-relative-hook                      cross/cwd-relative-hook.cmake)
sr_add_script_test(cross.cwd-relative-log                       cross/cwd-relative-log.cmake)
sr_add_script_test(cross.success-hook-with-success-retention    cross/success-hook-with-success-retention.cmake)
sr_add_script_test(cross.failure-hook-with-failure-retention    cross/failure-hook-with-failure-retention.cmake)
sr_add_script_test(cross.no-diagnostic-channel                  cross/no-diagnostic-channel.cmake)
sr_add_script_test(cross.no-parent-diagnostics-with-sr-log           cross/no-parent-diagnostics-with-sr-log.cmake)
