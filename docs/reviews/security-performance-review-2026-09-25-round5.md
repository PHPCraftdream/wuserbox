# Security and performance review — 2026-09-25 — round 5 — P0–P3

## Вердикт и проверенный срез

**Большинство замечаний раунда 4 закрыто. Подтверждённого нового P0 нет;
остаётся один P1 в fail-closed обработке identity lookup.** Для выпуска с
обещанием устойчивой файловой границы его следует закрыть. Для обычной работы
доверенных CLI этот срез существенно лучше предыдущего; оставшиеся P2 относятся
к profile-copy, а P3 — к расходу памяти. Это не доказательство отсутствия всех
уязвимостей: эксплуатационные программы и воспроизведение побегов не запускались.

Открыто: **P0 — 0; P1 — 1; P2 — 2; P3 — 2.** У P1 ниже отдельно указана
граница доказательства: неоднозначный ответ API принимается как успешный,
но его возникновение для исправной локальной группы песочницы не измерено.
Объявлять этот пункт подтверждённым побегом или P0 оснований нет.

Проверен **`acf756979ce6da748b151934bac2663f69af72c0`**. Дата HEAD —
22 сентября 2026; последние семь календарных дней этого среза — **16–22 сентября
включительно, 207 коммитов**. Дата имени отчёта обозначает раунд, а не наличие
в истории коммитов за 25 сентября. Изучены история изменений по подсистемам,
пять исправляющих коммитов после отчёта раунда 4 и текущая реализация целиком
по основным границам. Отдельного полного аудита каждого промежуточного commit
не было. Все номера строк ниже относятся к проверенному HEAD.

Просмотрены account → stub → restricted process, ConPTY/birth/own-console,
Shield и потоки, job/lease/stdio/teardown, ACL/grant/revoke/owner cap,
hard-link/path identity, profile creation/copy/cleanup, state/config/check/audit
и test/release workflows. Сопоставлены
[раунд 4](security-performance-review-2026-09-24-round4.md),
[раунд 3](security-performance-review-2026-09-23-round3.md),
[раунд 2](security-performance-review-2026-09-22-round2.md) и
[первый отчёт](security-performance-review-2026-09-20.md).

**CI проверенного SHA зелёный:**
[run 35731309661](https://github.com/PHPCraftdream/wuserbox/actions/runs/35731309661).
Сверён полный headSha; Test, Vet, Lint, Delete boundary, Registry hive picture
и Own console measurement завершены успешно. Прочитанный лог Delete boundary
содержит **80 PASS, 0 SKIP**; own-console шаг содержит оба обязательных PASS.

Работа выполнена в отдельном worktree. Production-код и существующие тесты
не менялись. Два небольших временных measurement-теста для profile-copy
созданы, выполнены и удалены; единственный сохраняемый файл — этот отчёт.
Локальные проверки использовали test TempDir, не пользовательские проекты;
UAC, создание учёток, видимые окна и нагрузочные прогоны не использовались.

## Что закрыто после раунда 4

| Прежний пункт | Результат на этом срезе |
| --- | --- |
| P1-1: owner SID после освобождения descriptor | Закрыт `1851e45`: `readable` вычисляет bool через `ownerDecision` до deferred Free; borrowed SID больше не выходит из функции. Адресный тест PASS. |
| P1-2: главный путь забирает блокирующий HPCON close | Закрыт `acf7569`: `claimClose` выполняется до запуска worker, последующие пути не получают владение. Stub defer использует `closePipes`. Проверены прежние и новые console-free ordering tests. |
| P1-3: ошибка lookup превращается в короткую identity list | Существенно исправлен: errno сохраняется, обычные lookup errors останавливают операции. Исключение для `ERROR_NONE_MAPPED` остаётся неоднозначным: P1-1 ниже. |
| P2-1: неизменный warm-forget O(E²) | Закрыт для прежнего случая: exact-spelling set и один resolver/index действительно убирают квадрат. Новые tests считают children, а не только ReadDir. Смешанный warm-copy сохраняет другой квадрат: P2-1 ниже. |
| P2-2: conhost oracle принимает частично неизвестный результат | Закрыт `9208198`: process/token/thread checks сохраняют unknown, verdict отказывает для живого host с таким ответом. Три обычных теста арифметики verdict PASS. |
| P2-3: copy ceiling основан только на старом Stat | Закрыт `7c90117`: проверка открытого source, ограниченный поток, повторный Stat перед Print. Growth/refusal и bounded-copy tests PASS. |
| P3-1: discarded heldEntry allocation в preflight | Закрыт `1851e45`: `carryable` проверяет ACE по одной; счётчиковый тест подтверждает отсутствие entry slice. |
| P3-2: process-wide SID lifetime в ACL operations | Закрыт в перечисленных прежним отчётом операциях: scoped Free в Set/Deny/Remove, operation-owned identities в Isolate/TakeBack/StripOwn, без глобального pin и per-object Parse в fromNothing. Баланс parses/frees на success/error/repeated calls PASS. |

Исправления не требуют возвращать старый write-restricted token или убирать
действующий owner cap. Resize регистрируется под тем же mutex, под которым
close запрещает новые обращения; worker ждёт уже зарегистрированные resize.
Прежний use-after-free HPCON по этому пути не обнаружен повторно.

## P1-1 — `ERROR_NONE_MAPPED` всё ещё разрешает успешную неполную identity list

**Статус:** остаток round 4 P1-3. **Confidence:** высокая для несоответствия
контракту API и ветвления кода; достижимость этого отказа при работе с исправной
локальной sandbox group не подтверждена живым измерением.

**Evidence.** `internal/win/acl/owner.go:256` создаёт список из исходного SID.
На `:268` любой wrapped `sid.NoneMapped` возвращает этот список успешно,
минуя member lookup. `internal/win/sid/sid.go:19` объясняет этот errno как
доказательство отсутствия principal; то же предположение закреплено
`TestTheIdentitiesKnowALookupThatFailedFromOneThatSaidNo`.

Но Microsoft прямо допускает `ERROR_NONE_MAPPED` при сетевом тайм-ауте
разрешения имени; это не универсальное доказательство, что SID никому не
принадлежит. [Контракт LookupAccountSidW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupaccountsidw).
Сохранение errno исправляет потерю причины, но само по себе не делает этот
конкретный errno однозначным.

**Impact.** Если production lookup существующей sandbox group возвращает
такой неопределённый ответ, Isolate/TakeBack/StripOwn получают только group SID,
без SID учётки, которой принадлежат файлы. Owner comparisons и удаление
account ACE тогда не распознают всю идентичность песочницы. Возможность
продолжить изменение ACL с неполным контекстом осталась. Это дефект fail-closed
контракта; управляемость условия из песочницы и реальное расширение доступа
этим путём здесь не доказаны. Обычные production группы локальны, поэтому
частоту и практическую достижимость нельзя выводить из сетевого примера API.

**Recommendation.** Передавать в production ACL-operation явно проверенные
group/account identities либо явное требование существующей sandbox group.
При таком требовании любой неуспешный lookup, включая `ERROR_NONE_MAPPED`,
должен остановить операцию. Synthetic SID для тестов и самостоятельный SID
пользователя следует обслуживать отдельным явно выбранным режимом, а не
угадывать допустимость сокращённого списка по общему errno. Ошибка поиска
member уже обрабатывается правильно — этот отказ сохранять.

**Tests.** Существующий тест с errno 1722 PASS и доказывает полезную часть fix.
Тест с `NoneMapped` тоже PASS, но закрепляет спорное разрешение. Нужен
неэксплуатационный unit test: операция с ожидаемой production group получает
`NoneMapped`, возвращает ошибку и не начинает ACL write; отдельный явный
synthetic-SID путь остаётся работоспособным.

## P2-1 — смешанный неизменный warm-copy по-прежнему делает O(E²) работы

**Статус:** новая, более узкая форма прежнего performance finding.
**Confidence:** высокая; измерено маленьким обычным тестом.

**Evidence.** `internal/policy/profile/copy.go:310` строит индекс всего record
для пропавшего source. После следующего существующего source `:329` вызывает
mirror, а `:338` безусловно сбрасывает индекс. Между тем
`mirror.go:233`–`:242` может целиком выйти по fingerprint fast-path — без
открытия source для копирования и без изменения destination.

Комментарий перед `stretch = nil` утверждает, что skipped warm file не
инвалидирует stretch; фактическое ветвление этого не различает. При чередовании
missing source и unchanged present source resolver/index перестраивается
после каждого такого no-op. Та же лишняя инвалидация возможна в
`forget.go:122`, когда clearEntry успешно ничего не удалил.

**Measurement.** В отдельной тестовой паре home/destination сначала выполнен
обычный copy файлов по четыре байта; затем удалена половина source entries
через один. Следующий Copy получил прежние fingerprints. Положительный
контроль: все entries сохранены в record, `openSource` вызван **0 раз**.

| Всего entries E | Resolver instances | Place resolutions | Обработано children |
| --- | --- | --- | --- |
| 4 | 2 | 8 | 8 |
| 8 | 4 | 32 | 32 |

Удвоение списка дало вчетверо больше работы при отсутствии копирования байтов.
Для этой формы это E/2 полных индексов по E entries, то есть Θ(E²).
Прежние полностью существующие и полностью отсутствующие списки уже линейны;
их исправление этим результатом не отменяется.

**Impact.** Лишние enumerations, resolutions и maps на каждом warm run с
частично доступными источниками. При большом настроенном списке это снова
заметная задержка старта; ошибки доступа или границы из этого пункта не следуют.

**Recommendation.** Возвращать из mirror/clearEntry факт изменения структуры
destination или вести operation-local mutation generation. Сбрасывать индекс
после изменения, а не после самого вызова. Содержимое файла и его имя — разные
изменения: индекс имён не обязательно инвалидировать после обычной перезаписи
байтов, но удаление, создание, rename и замена link обязаны его инвалидировать.

**Tests.** Закрепить смешанный список на 4/8 маленьких entries, считать
children/resolutions и иметь контроль `openSource == 0`. Сохранить regression
на реальную мутацию между двумя вопросами к resolver. Большой benchmark для
доказательства этой сложности не нужен.

## P2-2 — повторное достраивание alias-index портит уникальность уже известных имён

**Статус:** регрессия в `1aaa2f6`. **Confidence:** высокая; измерен неверный
ответ production resolver без изменения файлов между двумя резолюциями.

**Evidence.** В `internal/policy/profile/fold.go:416` индекс проверяется по
canonical path. Для ещё не найденного пути `:426` повторно сканирует children
и дополняет тот же `snap.byCanonical`. На `:451`–`:453` уже присутствующий
canonical path всегда становится `unique = false`, даже если он повторно
пришёл от **того же самого child**, а не от другого имени.

Индекс может законно быть частичным: Open или Canonical отдельного sibling
выше возвращает ошибку, и цикл делает continue. Восстановление доступа к этому
sibling запускает повторный scan и портит ранее успешные записи.

**Measurement.** Три обычных файла `a`, `b`, `c` в test TempDir. Пока `b`
занят кратким exclusive read handle, resolver успешно разрешает `A`; контроль
подтверждает, что `b` не вошёл в canonical map. Handle освобождён, `B` успешно
разрешается на втором scan. Затем тот же resolver отвечает для `C` пустым
путём и false; свежий resolver на тех же неизменных файлах отвечает `c`, true.
Имена, содержимое и ACL файлов в этом измерении не менялись.

**Impact.** False negative в операции, которая решает, сохранять ли запись
о скопированном содержимом. `newPlaceIndex` пропускает такие результаты,
`forget` использует отсутствие в индексе для решения об очистке, а
copyEntries — для сохранения record при отсутствующем source. Возможны
ненужная очистка или потеря записи о всё ещё существующей копии при respelling
и временной недоступности sibling. Сам факт ошибочной резолюции измерен;
сквозное удаление через Copy в этом раунде не воспроизводилось. Выхода за
границы os.Root эта ошибка не даёт.

**Recommendation.** Вставка одного child в индекс должна быть идемпотентной:
повторное наблюдение того же stored name не создаёт неоднозначность. Можно
собирать новый индекс из текущего canonical snapshot или дополнять прежний
только новыми child и сравнивать их имена. Не сводить неизвестный результат
резолюции к доказанному отсутствию перед потенциальной очисткой.

**Tests.** Нужен небольшой regression на частичный первый scan, успешный retry
другого sibling и последующую резолюцию ранее не запрошенного alias. Проверить
сохранение current entry/record. Нынешний
TestAliasAnswersAreKeptForTheQuestionsThatFollow проходит, потому что его
первый scan читает всех siblings успешно.

## P3-1 — bounded copy выделяет отдельные 32 KiB на каждый переносимый файл

**Статус:** безопасная возможность оптимизации после нового stream limit.
**Confidence:** высокая; подтверждено compiler escape analysis.

**Evidence.** `internal/policy/profile/mirror.go:393` делает
`make([]byte, 32<<10)` на каждый copyBounded. Компилятор Go 1.26.0 сообщает
`make([]byte, 32768) escapes to heap`. Даже файл из нескольких байт получает
этот scratch buffer. Это Θ(F × 32 KiB) суммарного allocation traffic при F
реально копируемых файлах; warm fingerprint skip эту allocation не делает.

**Impact.** Лишняя работа allocator/GC при большом числе мелких файлов.
Это не leak и не утверждение о регрессии относительно прежнего io.Copy:
производительность того переноса здесь отдельно не измерялась.

**Recommendation / tests.** Один лениво созданный scratch buffer на
последовательную copy-operation, передаваемый bounded copier. Между операциями
его не кэшировать бессрочно: он содержит фрагменты credential/settings files.
Вместо этого допустим локальный reusable buffer, lifetime которого заканчивается
с Copy. Сохранить chunk-before-write ceiling, short-write/error handling и
growth tests. Считать выделения самого scratch, не случайный общий allocs/op
Windows wrappers. Уменьшение buffer по размеру маленького source — ещё более
локальный вариант, если повторное использование сейчас усложнит API.

## P3-2 — scoped SID ownership ещё не доведён до token/account helpers

**Статус:** найдено вне исправленного ACL-operation context.
**Confidence:** высокая по владению native allocations.

**Evidence.** `internal/win/token/restricted.go:146`, `:150`, `:154` вызывают
sid.Parse для group/Everyone/Users и не освобождают успешные результаты,
включая выходы по ошибке после предыдущего Parse.
`internal/account/member.go:153` делает то же в BuiltinUsersName;
`account/account.go:126` — в InsideSandbox;
`account/ownprofile.go:286` и `:290` — в setHiveSecurity.
У sid.Parse есть явный sid.Free, и native память не управляется Go GC.

**Impact.** Небольшой native рост с числом вызовов в одном процессе.
В коротком CLI обычно малозаметен; это не прежний per-object ACL leak,
который устранён, и не основание задерживать выпуск после P1.

**Recommendation / tests.** Scoped `defer sid.Free` после каждого успешного
Parse там, где Windows-вызов копирует SID/ACL до возврата, с соблюдением lifetime
всех borrowed uintptr. Token owns свой результат, а не переданные временные
SID buffers. Для BuiltinUsersName достаточно проверить баланс Parses/Frees
за несколько вызовов; для token — success/error balance без запуска процессов.

## Остальная сложность, проверки и приёмка

Первый grant неизвестного существующего дерева с этой моделью требует как
минимум Ω(N) проверки объектов: каждый может иметь собственный ACL или внешний
hard link. Пропуск target/node_modules изменил бы гарантию. Параллелизм уменьшает
ожидание, но не отменяет нижнюю границу. Объединять preflight с первым ACL write
ради одного обхода также нельзя без смены обещания об отказе до модификаций.

Reorder window sweep ограничен числом workers, но общая память прохода не
только O(workers): pinned identity snapshots остаются O(S), в худшем случае
S=N. `pinned.prepare` всё ещё сравнивает посещаемые paths со списком pinned
entries, O(NP) в худшем случае. Для малого P это менее приоритетно, чем измеренный
P2-1. WalkDir/ReadDir(-1) удерживают списки children; один очень широкий каталог
может определять пик памяти независимо от числа workers.

В profile resolver карты canonical/byCanonical сейчас создаются даже для
каталогов, где используются только exact spellings. Ленивое создание этих двух
карт уберёт часть per-directory allocation traffic. Это дополнительный небольшой
резерв, не причина нового квадрата. Не следует заменять operation-local
snapshots межзапусковым кэшем без проверки изменений файловой системы.

Локальная среда: Go 1.26.0, windows/amd64. **33 top-level PASS, 0 SKIP**:

| Проверка | Результат |
| --- | --- |
| ACL identity/error/lifetime, owner decision и validation-only preflight | 10 PASS |
| Profile resolver/warm-copy/alias и copy-ceiling regressions | 10 PASS |
| Console-free relay close/resize/deferred cleanup и birth-list guards | 7 PASS |
| Чистые conhost verdict tests без процессов и опасных открытий | 3 PASS |
| SID Name errno preservation | 1 PASS |
| Два временных profile measurement-теста, включая cases 4/8 | 2 PASS; результаты приведены в P2 |
| Targeted profile compiler escape analysis | Успех; scratch buffer и snapshot maps на heap |

PASS двух measurements означает, что контрольные условия и наблюдение
выполнились; он не означает отсутствия дефекта. Временные файлы удалены,
постоянные regressions для новых P2 следует добавить при исправлении.
Ни один тест не упал. Первый вывод escape analysis был оборван ограничителем
PowerShell pipeline; повторная команда полностью потребила вывод и завершилась
с кодом 0. Полный локальный suite не запускался: для него прочитан уже
завершённый CI именно проверенного SHA.

Test/release используют версию Go из go.mod. Tag release по-прежнему может
стартовать независимо от main CI, а GoReleaser hook `go test ./...` сам по себе
не заменяет обязательные no-skip boundary и own-console steps. Для релиза нужно
удержать проверку того же выпускаемого SHA; текущий acf7569 этот CI уже прошёл.

Порядок исправлений: **P1-1 — явный production identity contract → P2-2 —
идемпотентность alias-index → P2-1 — инвалидация только после мутации → P3**.
Процентного ускорения или предельного RSS этот раунд не обещает: измерены
операции на маленьких fixtures и allocation sites, а не поведение больших
проектов под нагрузкой.

Документированные пределы Everyone/Users writable directories, доступного
чтения, сети, desktop/clipboard и ранее открытых handles остаются пределами
выбранной модели. Они не пересчитаны как новые findings; общего утверждения
«любая программа может менять только явно выданные директории» текущий механизм
не обеспечивает даже после исправления перечисленных ошибок.
