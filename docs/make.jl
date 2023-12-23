using Documenter
using LibSSH

makedocs(;
         repo=Remotes.GitHub("JamesWrigley", "LibSSH.jl"),
         sitename = "LibSSH",
         format = Documenter.HTML(
             prettyurls=get(ENV, "CI", "false") == "true",
             size_threshold=600000),
         modules = [LibSSH],
         warnonly=:missing_docs
         )
