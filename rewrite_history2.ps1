Set-Location "e:\BSCS\Projects\With Arslan\GRE FYP WORK (SHA SAAB)\Yadhav (Real Time Browser Extension Security)\Working"

git cherry-pick --abort
git checkout main
git branch -D new_history

$env:GIT_AUTHOR_NAME="Yadzzz0"
$env:GIT_AUTHOR_EMAIL="Yadhavelliah@gmail.com"
$env:GIT_COMMITTER_NAME="Yadzzz0"
$env:GIT_COMMITTER_EMAIL="Yadhavelliah@gmail.com"

git checkout -b new_history 4f3a4732f84f291461273617476696560ed67f63
git commit --amend --reset-author --no-edit

git cherry-pick 2cd60c8f3e5b0432abf6dc64b278a7d664bfcb4d
git commit --amend --reset-author --no-edit

git cherry-pick 2ef165f5b716c0fdf1e4f726f657623646d82d0e
git commit --amend --reset-author --no-edit

git cherry-pick 6b064151673b62d1a8cdd013694b464f787b5c77
git commit --amend --reset-author --no-edit

git cherry-pick 216660d0c9995f4be5d76693ac60fb833d153684
git commit --amend --reset-author --no-edit

git cherry-pick 6ad1a6a
git commit --amend --reset-author --no-edit

git checkout main
git reset --hard new_history
git log -10 --format="%h %an <%ae> %s"
