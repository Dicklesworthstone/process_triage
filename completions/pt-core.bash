_pt__core() {
    local i cur prev opts cmd
    COMPREPLY=()
    if [[ "${BASH_VERSINFO[0]}" -ge 4 ]]; then
        cur="$2"
    else
        cur="${COMP_WORDS[COMP_CWORD]}"
    fi
    prev="$3"
    cmd=""
    opts=""

    for i in "${COMP_WORDS[@]:0:COMP_CWORD}"
    do
        case "${cmd},${i}" in
            ",$1")
                cmd="pt__core"
                ;;
            pt__core,__deep-scan-worker)
                cmd="pt__core__subcmd____deep__subcmd__scan__subcmd__worker"
                ;;
            pt__core,agent)
                cmd="pt__core__subcmd__agent"
                ;;
            pt__core,bundle)
                cmd="pt__core__subcmd__bundle"
                ;;
            pt__core,check)
                cmd="pt__core__subcmd__check"
                ;;
            pt__core,completions)
                cmd="pt__core__subcmd__completions"
                ;;
            pt__core,config)
                cmd="pt__core__subcmd__config"
                ;;
            pt__core,daemon)
                cmd="pt__core__subcmd__daemon"
                ;;
            pt__core,deep-scan)
                cmd="pt__core__subcmd__deep__subcmd__scan"
                ;;
            pt__core,diff)
                cmd="pt__core__subcmd__diff"
                ;;
            pt__core,doctor)
                cmd="pt__core__subcmd__doctor"
                ;;
            pt__core,help)
                cmd="pt__core__subcmd__help"
                ;;
            pt__core,learn)
                cmd="pt__core__subcmd__learn"
                ;;
            pt__core,mcp)
                cmd="pt__core__subcmd__mcp"
                ;;
            pt__core,query)
                cmd="pt__core__subcmd__query"
                ;;
            pt__core,replay)
                cmd="pt__core__subcmd__replay"
                ;;
            pt__core,report)
                cmd="pt__core__subcmd__report"
                ;;
            pt__core,robot)
                cmd="pt__core__subcmd__agent"
                ;;
            pt__core,run)
                cmd="pt__core__subcmd__run"
                ;;
            pt__core,scan)
                cmd="pt__core__subcmd__scan"
                ;;
            pt__core,schema)
                cmd="pt__core__subcmd__schema"
                ;;
            pt__core,shadow)
                cmd="pt__core__subcmd__shadow"
                ;;
            pt__core,signature)
                cmd="pt__core__subcmd__signature"
                ;;
            pt__core,telemetry)
                cmd="pt__core__subcmd__telemetry"
                ;;
            pt__core,update)
                cmd="pt__core__subcmd__update"
                ;;
            pt__core,version)
                cmd="pt__core__subcmd__version"
                ;;
            pt__core__subcmd__agent,apply)
                cmd="pt__core__subcmd__agent__subcmd__apply"
                ;;
            pt__core__subcmd__agent,capabilities)
                cmd="pt__core__subcmd__agent__subcmd__capabilities"
                ;;
            pt__core__subcmd__agent,diff)
                cmd="pt__core__subcmd__agent__subcmd__diff"
                ;;
            pt__core__subcmd__agent,explain)
                cmd="pt__core__subcmd__agent__subcmd__explain"
                ;;
            pt__core__subcmd__agent,export)
                cmd="pt__core__subcmd__agent__subcmd__export"
                ;;
            pt__core__subcmd__agent,export-priors)
                cmd="pt__core__subcmd__agent__subcmd__export__subcmd__priors"
                ;;
            pt__core__subcmd__agent,fleet)
                cmd="pt__core__subcmd__agent__subcmd__fleet"
                ;;
            pt__core__subcmd__agent,help)
                cmd="pt__core__subcmd__agent__subcmd__help"
                ;;
            pt__core__subcmd__agent,import-priors)
                cmd="pt__core__subcmd__agent__subcmd__import__subcmd__priors"
                ;;
            pt__core__subcmd__agent,inbox)
                cmd="pt__core__subcmd__agent__subcmd__inbox"
                ;;
            pt__core__subcmd__agent,init)
                cmd="pt__core__subcmd__agent__subcmd__init"
                ;;
            pt__core__subcmd__agent,label)
                cmd="pt__core__subcmd__agent__subcmd__label"
                ;;
            pt__core__subcmd__agent,list-priors)
                cmd="pt__core__subcmd__agent__subcmd__list__subcmd__priors"
                ;;
            pt__core__subcmd__agent,plan)
                cmd="pt__core__subcmd__agent__subcmd__plan"
                ;;
            pt__core__subcmd__agent,report)
                cmd="pt__core__subcmd__agent__subcmd__report"
                ;;
            pt__core__subcmd__agent,sessions)
                cmd="pt__core__subcmd__agent__subcmd__sessions"
                ;;
            pt__core__subcmd__agent,snapshot)
                cmd="pt__core__subcmd__agent__subcmd__snapshot"
                ;;
            pt__core__subcmd__agent,tail)
                cmd="pt__core__subcmd__agent__subcmd__tail"
                ;;
            pt__core__subcmd__agent,undo)
                cmd="pt__core__subcmd__agent__subcmd__undo"
                ;;
            pt__core__subcmd__agent,verify)
                cmd="pt__core__subcmd__agent__subcmd__verify"
                ;;
            pt__core__subcmd__agent,watch)
                cmd="pt__core__subcmd__agent__subcmd__watch"
                ;;
            pt__core__subcmd__agent__subcmd__fleet,apply)
                cmd="pt__core__subcmd__agent__subcmd__fleet__subcmd__apply"
                ;;
            pt__core__subcmd__agent__subcmd__fleet,doctor)
                cmd="pt__core__subcmd__agent__subcmd__fleet__subcmd__doctor"
                ;;
            pt__core__subcmd__agent__subcmd__fleet,health)
                cmd="pt__core__subcmd__agent__subcmd__fleet__subcmd__health"
                ;;
            pt__core__subcmd__agent__subcmd__fleet,help)
                cmd="pt__core__subcmd__agent__subcmd__fleet__subcmd__help"
                ;;
            pt__core__subcmd__agent__subcmd__fleet,inventory)
                cmd="pt__core__subcmd__agent__subcmd__fleet__subcmd__inventory"
                ;;
            pt__core__subcmd__agent__subcmd__fleet,plan)
                cmd="pt__core__subcmd__agent__subcmd__fleet__subcmd__plan"
                ;;
            pt__core__subcmd__agent__subcmd__fleet,report)
                cmd="pt__core__subcmd__agent__subcmd__fleet__subcmd__report"
                ;;
            pt__core__subcmd__agent__subcmd__fleet,status)
                cmd="pt__core__subcmd__agent__subcmd__fleet__subcmd__status"
                ;;
            pt__core__subcmd__agent__subcmd__fleet,transfer)
                cmd="pt__core__subcmd__agent__subcmd__fleet__subcmd__transfer"
                ;;
            pt__core__subcmd__agent__subcmd__fleet__subcmd__help,apply)
                cmd="pt__core__subcmd__agent__subcmd__fleet__subcmd__help__subcmd__apply"
                ;;
            pt__core__subcmd__agent__subcmd__fleet__subcmd__help,doctor)
                cmd="pt__core__subcmd__agent__subcmd__fleet__subcmd__help__subcmd__doctor"
                ;;
            pt__core__subcmd__agent__subcmd__fleet__subcmd__help,health)
                cmd="pt__core__subcmd__agent__subcmd__fleet__subcmd__help__subcmd__health"
                ;;
            pt__core__subcmd__agent__subcmd__fleet__subcmd__help,help)
                cmd="pt__core__subcmd__agent__subcmd__fleet__subcmd__help__subcmd__help"
                ;;
            pt__core__subcmd__agent__subcmd__fleet__subcmd__help,inventory)
                cmd="pt__core__subcmd__agent__subcmd__fleet__subcmd__help__subcmd__inventory"
                ;;
            pt__core__subcmd__agent__subcmd__fleet__subcmd__help,plan)
                cmd="pt__core__subcmd__agent__subcmd__fleet__subcmd__help__subcmd__plan"
                ;;
            pt__core__subcmd__agent__subcmd__fleet__subcmd__help,report)
                cmd="pt__core__subcmd__agent__subcmd__fleet__subcmd__help__subcmd__report"
                ;;
            pt__core__subcmd__agent__subcmd__fleet__subcmd__help,status)
                cmd="pt__core__subcmd__agent__subcmd__fleet__subcmd__help__subcmd__status"
                ;;
            pt__core__subcmd__agent__subcmd__fleet__subcmd__help,transfer)
                cmd="pt__core__subcmd__agent__subcmd__fleet__subcmd__help__subcmd__transfer"
                ;;
            pt__core__subcmd__agent__subcmd__fleet__subcmd__help__subcmd__transfer,diff)
                cmd="pt__core__subcmd__agent__subcmd__fleet__subcmd__help__subcmd__transfer__subcmd__diff"
                ;;
            pt__core__subcmd__agent__subcmd__fleet__subcmd__help__subcmd__transfer,export)
                cmd="pt__core__subcmd__agent__subcmd__fleet__subcmd__help__subcmd__transfer__subcmd__export"
                ;;
            pt__core__subcmd__agent__subcmd__fleet__subcmd__help__subcmd__transfer,import)
                cmd="pt__core__subcmd__agent__subcmd__fleet__subcmd__help__subcmd__transfer__subcmd__import"
                ;;
            pt__core__subcmd__agent__subcmd__fleet__subcmd__transfer,diff)
                cmd="pt__core__subcmd__agent__subcmd__fleet__subcmd__transfer__subcmd__diff"
                ;;
            pt__core__subcmd__agent__subcmd__fleet__subcmd__transfer,export)
                cmd="pt__core__subcmd__agent__subcmd__fleet__subcmd__transfer__subcmd__export"
                ;;
            pt__core__subcmd__agent__subcmd__fleet__subcmd__transfer,help)
                cmd="pt__core__subcmd__agent__subcmd__fleet__subcmd__transfer__subcmd__help"
                ;;
            pt__core__subcmd__agent__subcmd__fleet__subcmd__transfer,import)
                cmd="pt__core__subcmd__agent__subcmd__fleet__subcmd__transfer__subcmd__import"
                ;;
            pt__core__subcmd__agent__subcmd__fleet__subcmd__transfer__subcmd__help,diff)
                cmd="pt__core__subcmd__agent__subcmd__fleet__subcmd__transfer__subcmd__help__subcmd__diff"
                ;;
            pt__core__subcmd__agent__subcmd__fleet__subcmd__transfer__subcmd__help,export)
                cmd="pt__core__subcmd__agent__subcmd__fleet__subcmd__transfer__subcmd__help__subcmd__export"
                ;;
            pt__core__subcmd__agent__subcmd__fleet__subcmd__transfer__subcmd__help,help)
                cmd="pt__core__subcmd__agent__subcmd__fleet__subcmd__transfer__subcmd__help__subcmd__help"
                ;;
            pt__core__subcmd__agent__subcmd__fleet__subcmd__transfer__subcmd__help,import)
                cmd="pt__core__subcmd__agent__subcmd__fleet__subcmd__transfer__subcmd__help__subcmd__import"
                ;;
            pt__core__subcmd__agent__subcmd__help,apply)
                cmd="pt__core__subcmd__agent__subcmd__help__subcmd__apply"
                ;;
            pt__core__subcmd__agent__subcmd__help,capabilities)
                cmd="pt__core__subcmd__agent__subcmd__help__subcmd__capabilities"
                ;;
            pt__core__subcmd__agent__subcmd__help,diff)
                cmd="pt__core__subcmd__agent__subcmd__help__subcmd__diff"
                ;;
            pt__core__subcmd__agent__subcmd__help,explain)
                cmd="pt__core__subcmd__agent__subcmd__help__subcmd__explain"
                ;;
            pt__core__subcmd__agent__subcmd__help,export)
                cmd="pt__core__subcmd__agent__subcmd__help__subcmd__export"
                ;;
            pt__core__subcmd__agent__subcmd__help,export-priors)
                cmd="pt__core__subcmd__agent__subcmd__help__subcmd__export__subcmd__priors"
                ;;
            pt__core__subcmd__agent__subcmd__help,fleet)
                cmd="pt__core__subcmd__agent__subcmd__help__subcmd__fleet"
                ;;
            pt__core__subcmd__agent__subcmd__help,help)
                cmd="pt__core__subcmd__agent__subcmd__help__subcmd__help"
                ;;
            pt__core__subcmd__agent__subcmd__help,import-priors)
                cmd="pt__core__subcmd__agent__subcmd__help__subcmd__import__subcmd__priors"
                ;;
            pt__core__subcmd__agent__subcmd__help,inbox)
                cmd="pt__core__subcmd__agent__subcmd__help__subcmd__inbox"
                ;;
            pt__core__subcmd__agent__subcmd__help,init)
                cmd="pt__core__subcmd__agent__subcmd__help__subcmd__init"
                ;;
            pt__core__subcmd__agent__subcmd__help,label)
                cmd="pt__core__subcmd__agent__subcmd__help__subcmd__label"
                ;;
            pt__core__subcmd__agent__subcmd__help,list-priors)
                cmd="pt__core__subcmd__agent__subcmd__help__subcmd__list__subcmd__priors"
                ;;
            pt__core__subcmd__agent__subcmd__help,plan)
                cmd="pt__core__subcmd__agent__subcmd__help__subcmd__plan"
                ;;
            pt__core__subcmd__agent__subcmd__help,report)
                cmd="pt__core__subcmd__agent__subcmd__help__subcmd__report"
                ;;
            pt__core__subcmd__agent__subcmd__help,sessions)
                cmd="pt__core__subcmd__agent__subcmd__help__subcmd__sessions"
                ;;
            pt__core__subcmd__agent__subcmd__help,snapshot)
                cmd="pt__core__subcmd__agent__subcmd__help__subcmd__snapshot"
                ;;
            pt__core__subcmd__agent__subcmd__help,tail)
                cmd="pt__core__subcmd__agent__subcmd__help__subcmd__tail"
                ;;
            pt__core__subcmd__agent__subcmd__help,undo)
                cmd="pt__core__subcmd__agent__subcmd__help__subcmd__undo"
                ;;
            pt__core__subcmd__agent__subcmd__help,verify)
                cmd="pt__core__subcmd__agent__subcmd__help__subcmd__verify"
                ;;
            pt__core__subcmd__agent__subcmd__help,watch)
                cmd="pt__core__subcmd__agent__subcmd__help__subcmd__watch"
                ;;
            pt__core__subcmd__agent__subcmd__help__subcmd__fleet,apply)
                cmd="pt__core__subcmd__agent__subcmd__help__subcmd__fleet__subcmd__apply"
                ;;
            pt__core__subcmd__agent__subcmd__help__subcmd__fleet,doctor)
                cmd="pt__core__subcmd__agent__subcmd__help__subcmd__fleet__subcmd__doctor"
                ;;
            pt__core__subcmd__agent__subcmd__help__subcmd__fleet,health)
                cmd="pt__core__subcmd__agent__subcmd__help__subcmd__fleet__subcmd__health"
                ;;
            pt__core__subcmd__agent__subcmd__help__subcmd__fleet,inventory)
                cmd="pt__core__subcmd__agent__subcmd__help__subcmd__fleet__subcmd__inventory"
                ;;
            pt__core__subcmd__agent__subcmd__help__subcmd__fleet,plan)
                cmd="pt__core__subcmd__agent__subcmd__help__subcmd__fleet__subcmd__plan"
                ;;
            pt__core__subcmd__agent__subcmd__help__subcmd__fleet,report)
                cmd="pt__core__subcmd__agent__subcmd__help__subcmd__fleet__subcmd__report"
                ;;
            pt__core__subcmd__agent__subcmd__help__subcmd__fleet,status)
                cmd="pt__core__subcmd__agent__subcmd__help__subcmd__fleet__subcmd__status"
                ;;
            pt__core__subcmd__agent__subcmd__help__subcmd__fleet,transfer)
                cmd="pt__core__subcmd__agent__subcmd__help__subcmd__fleet__subcmd__transfer"
                ;;
            pt__core__subcmd__agent__subcmd__help__subcmd__fleet__subcmd__transfer,diff)
                cmd="pt__core__subcmd__agent__subcmd__help__subcmd__fleet__subcmd__transfer__subcmd__diff"
                ;;
            pt__core__subcmd__agent__subcmd__help__subcmd__fleet__subcmd__transfer,export)
                cmd="pt__core__subcmd__agent__subcmd__help__subcmd__fleet__subcmd__transfer__subcmd__export"
                ;;
            pt__core__subcmd__agent__subcmd__help__subcmd__fleet__subcmd__transfer,import)
                cmd="pt__core__subcmd__agent__subcmd__help__subcmd__fleet__subcmd__transfer__subcmd__import"
                ;;
            pt__core__subcmd__bundle,create)
                cmd="pt__core__subcmd__bundle__subcmd__create"
                ;;
            pt__core__subcmd__bundle,extract)
                cmd="pt__core__subcmd__bundle__subcmd__extract"
                ;;
            pt__core__subcmd__bundle,help)
                cmd="pt__core__subcmd__bundle__subcmd__help"
                ;;
            pt__core__subcmd__bundle,inspect)
                cmd="pt__core__subcmd__bundle__subcmd__inspect"
                ;;
            pt__core__subcmd__bundle__subcmd__help,create)
                cmd="pt__core__subcmd__bundle__subcmd__help__subcmd__create"
                ;;
            pt__core__subcmd__bundle__subcmd__help,extract)
                cmd="pt__core__subcmd__bundle__subcmd__help__subcmd__extract"
                ;;
            pt__core__subcmd__bundle__subcmd__help,help)
                cmd="pt__core__subcmd__bundle__subcmd__help__subcmd__help"
                ;;
            pt__core__subcmd__bundle__subcmd__help,inspect)
                cmd="pt__core__subcmd__bundle__subcmd__help__subcmd__inspect"
                ;;
            pt__core__subcmd__config,diff-preset)
                cmd="pt__core__subcmd__config__subcmd__diff__subcmd__preset"
                ;;
            pt__core__subcmd__config,export-preset)
                cmd="pt__core__subcmd__config__subcmd__export__subcmd__preset"
                ;;
            pt__core__subcmd__config,help)
                cmd="pt__core__subcmd__config__subcmd__help"
                ;;
            pt__core__subcmd__config,list-presets)
                cmd="pt__core__subcmd__config__subcmd__list__subcmd__presets"
                ;;
            pt__core__subcmd__config,schema)
                cmd="pt__core__subcmd__config__subcmd__schema"
                ;;
            pt__core__subcmd__config,show)
                cmd="pt__core__subcmd__config__subcmd__show"
                ;;
            pt__core__subcmd__config,show-preset)
                cmd="pt__core__subcmd__config__subcmd__show__subcmd__preset"
                ;;
            pt__core__subcmd__config,validate)
                cmd="pt__core__subcmd__config__subcmd__validate"
                ;;
            pt__core__subcmd__config__subcmd__help,diff-preset)
                cmd="pt__core__subcmd__config__subcmd__help__subcmd__diff__subcmd__preset"
                ;;
            pt__core__subcmd__config__subcmd__help,export-preset)
                cmd="pt__core__subcmd__config__subcmd__help__subcmd__export__subcmd__preset"
                ;;
            pt__core__subcmd__config__subcmd__help,help)
                cmd="pt__core__subcmd__config__subcmd__help__subcmd__help"
                ;;
            pt__core__subcmd__config__subcmd__help,list-presets)
                cmd="pt__core__subcmd__config__subcmd__help__subcmd__list__subcmd__presets"
                ;;
            pt__core__subcmd__config__subcmd__help,schema)
                cmd="pt__core__subcmd__config__subcmd__help__subcmd__schema"
                ;;
            pt__core__subcmd__config__subcmd__help,show)
                cmd="pt__core__subcmd__config__subcmd__help__subcmd__show"
                ;;
            pt__core__subcmd__config__subcmd__help,show-preset)
                cmd="pt__core__subcmd__config__subcmd__help__subcmd__show__subcmd__preset"
                ;;
            pt__core__subcmd__config__subcmd__help,validate)
                cmd="pt__core__subcmd__config__subcmd__help__subcmd__validate"
                ;;
            pt__core__subcmd__daemon,help)
                cmd="pt__core__subcmd__daemon__subcmd__help"
                ;;
            pt__core__subcmd__daemon,install)
                cmd="pt__core__subcmd__daemon__subcmd__install"
                ;;
            pt__core__subcmd__daemon,service-status)
                cmd="pt__core__subcmd__daemon__subcmd__service__subcmd__status"
                ;;
            pt__core__subcmd__daemon,start)
                cmd="pt__core__subcmd__daemon__subcmd__start"
                ;;
            pt__core__subcmd__daemon,status)
                cmd="pt__core__subcmd__daemon__subcmd__status"
                ;;
            pt__core__subcmd__daemon,stop)
                cmd="pt__core__subcmd__daemon__subcmd__stop"
                ;;
            pt__core__subcmd__daemon,uninstall)
                cmd="pt__core__subcmd__daemon__subcmd__uninstall"
                ;;
            pt__core__subcmd__daemon__subcmd__help,help)
                cmd="pt__core__subcmd__daemon__subcmd__help__subcmd__help"
                ;;
            pt__core__subcmd__daemon__subcmd__help,install)
                cmd="pt__core__subcmd__daemon__subcmd__help__subcmd__install"
                ;;
            pt__core__subcmd__daemon__subcmd__help,service-status)
                cmd="pt__core__subcmd__daemon__subcmd__help__subcmd__service__subcmd__status"
                ;;
            pt__core__subcmd__daemon__subcmd__help,start)
                cmd="pt__core__subcmd__daemon__subcmd__help__subcmd__start"
                ;;
            pt__core__subcmd__daemon__subcmd__help,status)
                cmd="pt__core__subcmd__daemon__subcmd__help__subcmd__status"
                ;;
            pt__core__subcmd__daemon__subcmd__help,stop)
                cmd="pt__core__subcmd__daemon__subcmd__help__subcmd__stop"
                ;;
            pt__core__subcmd__daemon__subcmd__help,uninstall)
                cmd="pt__core__subcmd__daemon__subcmd__help__subcmd__uninstall"
                ;;
            pt__core__subcmd__help,__deep-scan-worker)
                cmd="pt__core__subcmd__help__subcmd____deep__subcmd__scan__subcmd__worker"
                ;;
            pt__core__subcmd__help,agent)
                cmd="pt__core__subcmd__help__subcmd__agent"
                ;;
            pt__core__subcmd__help,bundle)
                cmd="pt__core__subcmd__help__subcmd__bundle"
                ;;
            pt__core__subcmd__help,check)
                cmd="pt__core__subcmd__help__subcmd__check"
                ;;
            pt__core__subcmd__help,completions)
                cmd="pt__core__subcmd__help__subcmd__completions"
                ;;
            pt__core__subcmd__help,config)
                cmd="pt__core__subcmd__help__subcmd__config"
                ;;
            pt__core__subcmd__help,daemon)
                cmd="pt__core__subcmd__help__subcmd__daemon"
                ;;
            pt__core__subcmd__help,deep-scan)
                cmd="pt__core__subcmd__help__subcmd__deep__subcmd__scan"
                ;;
            pt__core__subcmd__help,diff)
                cmd="pt__core__subcmd__help__subcmd__diff"
                ;;
            pt__core__subcmd__help,doctor)
                cmd="pt__core__subcmd__help__subcmd__doctor"
                ;;
            pt__core__subcmd__help,help)
                cmd="pt__core__subcmd__help__subcmd__help"
                ;;
            pt__core__subcmd__help,learn)
                cmd="pt__core__subcmd__help__subcmd__learn"
                ;;
            pt__core__subcmd__help,mcp)
                cmd="pt__core__subcmd__help__subcmd__mcp"
                ;;
            pt__core__subcmd__help,query)
                cmd="pt__core__subcmd__help__subcmd__query"
                ;;
            pt__core__subcmd__help,replay)
                cmd="pt__core__subcmd__help__subcmd__replay"
                ;;
            pt__core__subcmd__help,report)
                cmd="pt__core__subcmd__help__subcmd__report"
                ;;
            pt__core__subcmd__help,run)
                cmd="pt__core__subcmd__help__subcmd__run"
                ;;
            pt__core__subcmd__help,scan)
                cmd="pt__core__subcmd__help__subcmd__scan"
                ;;
            pt__core__subcmd__help,schema)
                cmd="pt__core__subcmd__help__subcmd__schema"
                ;;
            pt__core__subcmd__help,shadow)
                cmd="pt__core__subcmd__help__subcmd__shadow"
                ;;
            pt__core__subcmd__help,signature)
                cmd="pt__core__subcmd__help__subcmd__signature"
                ;;
            pt__core__subcmd__help,telemetry)
                cmd="pt__core__subcmd__help__subcmd__telemetry"
                ;;
            pt__core__subcmd__help,update)
                cmd="pt__core__subcmd__help__subcmd__update"
                ;;
            pt__core__subcmd__help,version)
                cmd="pt__core__subcmd__help__subcmd__version"
                ;;
            pt__core__subcmd__help__subcmd__agent,apply)
                cmd="pt__core__subcmd__help__subcmd__agent__subcmd__apply"
                ;;
            pt__core__subcmd__help__subcmd__agent,capabilities)
                cmd="pt__core__subcmd__help__subcmd__agent__subcmd__capabilities"
                ;;
            pt__core__subcmd__help__subcmd__agent,diff)
                cmd="pt__core__subcmd__help__subcmd__agent__subcmd__diff"
                ;;
            pt__core__subcmd__help__subcmd__agent,explain)
                cmd="pt__core__subcmd__help__subcmd__agent__subcmd__explain"
                ;;
            pt__core__subcmd__help__subcmd__agent,export)
                cmd="pt__core__subcmd__help__subcmd__agent__subcmd__export"
                ;;
            pt__core__subcmd__help__subcmd__agent,export-priors)
                cmd="pt__core__subcmd__help__subcmd__agent__subcmd__export__subcmd__priors"
                ;;
            pt__core__subcmd__help__subcmd__agent,fleet)
                cmd="pt__core__subcmd__help__subcmd__agent__subcmd__fleet"
                ;;
            pt__core__subcmd__help__subcmd__agent,import-priors)
                cmd="pt__core__subcmd__help__subcmd__agent__subcmd__import__subcmd__priors"
                ;;
            pt__core__subcmd__help__subcmd__agent,inbox)
                cmd="pt__core__subcmd__help__subcmd__agent__subcmd__inbox"
                ;;
            pt__core__subcmd__help__subcmd__agent,init)
                cmd="pt__core__subcmd__help__subcmd__agent__subcmd__init"
                ;;
            pt__core__subcmd__help__subcmd__agent,label)
                cmd="pt__core__subcmd__help__subcmd__agent__subcmd__label"
                ;;
            pt__core__subcmd__help__subcmd__agent,list-priors)
                cmd="pt__core__subcmd__help__subcmd__agent__subcmd__list__subcmd__priors"
                ;;
            pt__core__subcmd__help__subcmd__agent,plan)
                cmd="pt__core__subcmd__help__subcmd__agent__subcmd__plan"
                ;;
            pt__core__subcmd__help__subcmd__agent,report)
                cmd="pt__core__subcmd__help__subcmd__agent__subcmd__report"
                ;;
            pt__core__subcmd__help__subcmd__agent,sessions)
                cmd="pt__core__subcmd__help__subcmd__agent__subcmd__sessions"
                ;;
            pt__core__subcmd__help__subcmd__agent,snapshot)
                cmd="pt__core__subcmd__help__subcmd__agent__subcmd__snapshot"
                ;;
            pt__core__subcmd__help__subcmd__agent,tail)
                cmd="pt__core__subcmd__help__subcmd__agent__subcmd__tail"
                ;;
            pt__core__subcmd__help__subcmd__agent,undo)
                cmd="pt__core__subcmd__help__subcmd__agent__subcmd__undo"
                ;;
            pt__core__subcmd__help__subcmd__agent,verify)
                cmd="pt__core__subcmd__help__subcmd__agent__subcmd__verify"
                ;;
            pt__core__subcmd__help__subcmd__agent,watch)
                cmd="pt__core__subcmd__help__subcmd__agent__subcmd__watch"
                ;;
            pt__core__subcmd__help__subcmd__agent__subcmd__fleet,apply)
                cmd="pt__core__subcmd__help__subcmd__agent__subcmd__fleet__subcmd__apply"
                ;;
            pt__core__subcmd__help__subcmd__agent__subcmd__fleet,doctor)
                cmd="pt__core__subcmd__help__subcmd__agent__subcmd__fleet__subcmd__doctor"
                ;;
            pt__core__subcmd__help__subcmd__agent__subcmd__fleet,health)
                cmd="pt__core__subcmd__help__subcmd__agent__subcmd__fleet__subcmd__health"
                ;;
            pt__core__subcmd__help__subcmd__agent__subcmd__fleet,inventory)
                cmd="pt__core__subcmd__help__subcmd__agent__subcmd__fleet__subcmd__inventory"
                ;;
            pt__core__subcmd__help__subcmd__agent__subcmd__fleet,plan)
                cmd="pt__core__subcmd__help__subcmd__agent__subcmd__fleet__subcmd__plan"
                ;;
            pt__core__subcmd__help__subcmd__agent__subcmd__fleet,report)
                cmd="pt__core__subcmd__help__subcmd__agent__subcmd__fleet__subcmd__report"
                ;;
            pt__core__subcmd__help__subcmd__agent__subcmd__fleet,status)
                cmd="pt__core__subcmd__help__subcmd__agent__subcmd__fleet__subcmd__status"
                ;;
            pt__core__subcmd__help__subcmd__agent__subcmd__fleet,transfer)
                cmd="pt__core__subcmd__help__subcmd__agent__subcmd__fleet__subcmd__transfer"
                ;;
            pt__core__subcmd__help__subcmd__agent__subcmd__fleet__subcmd__transfer,diff)
                cmd="pt__core__subcmd__help__subcmd__agent__subcmd__fleet__subcmd__transfer__subcmd__diff"
                ;;
            pt__core__subcmd__help__subcmd__agent__subcmd__fleet__subcmd__transfer,export)
                cmd="pt__core__subcmd__help__subcmd__agent__subcmd__fleet__subcmd__transfer__subcmd__export"
                ;;
            pt__core__subcmd__help__subcmd__agent__subcmd__fleet__subcmd__transfer,import)
                cmd="pt__core__subcmd__help__subcmd__agent__subcmd__fleet__subcmd__transfer__subcmd__import"
                ;;
            pt__core__subcmd__help__subcmd__bundle,create)
                cmd="pt__core__subcmd__help__subcmd__bundle__subcmd__create"
                ;;
            pt__core__subcmd__help__subcmd__bundle,extract)
                cmd="pt__core__subcmd__help__subcmd__bundle__subcmd__extract"
                ;;
            pt__core__subcmd__help__subcmd__bundle,inspect)
                cmd="pt__core__subcmd__help__subcmd__bundle__subcmd__inspect"
                ;;
            pt__core__subcmd__help__subcmd__config,diff-preset)
                cmd="pt__core__subcmd__help__subcmd__config__subcmd__diff__subcmd__preset"
                ;;
            pt__core__subcmd__help__subcmd__config,export-preset)
                cmd="pt__core__subcmd__help__subcmd__config__subcmd__export__subcmd__preset"
                ;;
            pt__core__subcmd__help__subcmd__config,list-presets)
                cmd="pt__core__subcmd__help__subcmd__config__subcmd__list__subcmd__presets"
                ;;
            pt__core__subcmd__help__subcmd__config,schema)
                cmd="pt__core__subcmd__help__subcmd__config__subcmd__schema"
                ;;
            pt__core__subcmd__help__subcmd__config,show)
                cmd="pt__core__subcmd__help__subcmd__config__subcmd__show"
                ;;
            pt__core__subcmd__help__subcmd__config,show-preset)
                cmd="pt__core__subcmd__help__subcmd__config__subcmd__show__subcmd__preset"
                ;;
            pt__core__subcmd__help__subcmd__config,validate)
                cmd="pt__core__subcmd__help__subcmd__config__subcmd__validate"
                ;;
            pt__core__subcmd__help__subcmd__daemon,install)
                cmd="pt__core__subcmd__help__subcmd__daemon__subcmd__install"
                ;;
            pt__core__subcmd__help__subcmd__daemon,service-status)
                cmd="pt__core__subcmd__help__subcmd__daemon__subcmd__service__subcmd__status"
                ;;
            pt__core__subcmd__help__subcmd__daemon,start)
                cmd="pt__core__subcmd__help__subcmd__daemon__subcmd__start"
                ;;
            pt__core__subcmd__help__subcmd__daemon,status)
                cmd="pt__core__subcmd__help__subcmd__daemon__subcmd__status"
                ;;
            pt__core__subcmd__help__subcmd__daemon,stop)
                cmd="pt__core__subcmd__help__subcmd__daemon__subcmd__stop"
                ;;
            pt__core__subcmd__help__subcmd__daemon,uninstall)
                cmd="pt__core__subcmd__help__subcmd__daemon__subcmd__uninstall"
                ;;
            pt__core__subcmd__help__subcmd__learn,complete)
                cmd="pt__core__subcmd__help__subcmd__learn__subcmd__complete"
                ;;
            pt__core__subcmd__help__subcmd__learn,list)
                cmd="pt__core__subcmd__help__subcmd__learn__subcmd__list"
                ;;
            pt__core__subcmd__help__subcmd__learn,reset)
                cmd="pt__core__subcmd__help__subcmd__learn__subcmd__reset"
                ;;
            pt__core__subcmd__help__subcmd__learn,show)
                cmd="pt__core__subcmd__help__subcmd__learn__subcmd__show"
                ;;
            pt__core__subcmd__help__subcmd__learn,verify)
                cmd="pt__core__subcmd__help__subcmd__learn__subcmd__verify"
                ;;
            pt__core__subcmd__help__subcmd__query,actions)
                cmd="pt__core__subcmd__help__subcmd__query__subcmd__actions"
                ;;
            pt__core__subcmd__help__subcmd__query,sessions)
                cmd="pt__core__subcmd__help__subcmd__query__subcmd__sessions"
                ;;
            pt__core__subcmd__help__subcmd__query,telemetry)
                cmd="pt__core__subcmd__help__subcmd__query__subcmd__telemetry"
                ;;
            pt__core__subcmd__help__subcmd__replay,evaluate)
                cmd="pt__core__subcmd__help__subcmd__replay__subcmd__evaluate"
                ;;
            pt__core__subcmd__help__subcmd__replay,label-template)
                cmd="pt__core__subcmd__help__subcmd__replay__subcmd__label__subcmd__template"
                ;;
            pt__core__subcmd__help__subcmd__replay,refit)
                cmd="pt__core__subcmd__help__subcmd__replay__subcmd__refit"
                ;;
            pt__core__subcmd__help__subcmd__shadow,export)
                cmd="pt__core__subcmd__help__subcmd__shadow__subcmd__export"
                ;;
            pt__core__subcmd__help__subcmd__shadow,report)
                cmd="pt__core__subcmd__help__subcmd__shadow__subcmd__report"
                ;;
            pt__core__subcmd__help__subcmd__shadow,run)
                cmd="pt__core__subcmd__help__subcmd__shadow__subcmd__run"
                ;;
            pt__core__subcmd__help__subcmd__shadow,start)
                cmd="pt__core__subcmd__help__subcmd__shadow__subcmd__start"
                ;;
            pt__core__subcmd__help__subcmd__shadow,status)
                cmd="pt__core__subcmd__help__subcmd__shadow__subcmd__status"
                ;;
            pt__core__subcmd__help__subcmd__shadow,stop)
                cmd="pt__core__subcmd__help__subcmd__shadow__subcmd__stop"
                ;;
            pt__core__subcmd__help__subcmd__signature,add)
                cmd="pt__core__subcmd__help__subcmd__signature__subcmd__add"
                ;;
            pt__core__subcmd__help__subcmd__signature,disable)
                cmd="pt__core__subcmd__help__subcmd__signature__subcmd__disable"
                ;;
            pt__core__subcmd__help__subcmd__signature,enable)
                cmd="pt__core__subcmd__help__subcmd__signature__subcmd__enable"
                ;;
            pt__core__subcmd__help__subcmd__signature,export)
                cmd="pt__core__subcmd__help__subcmd__signature__subcmd__export"
                ;;
            pt__core__subcmd__help__subcmd__signature,import)
                cmd="pt__core__subcmd__help__subcmd__signature__subcmd__import"
                ;;
            pt__core__subcmd__help__subcmd__signature,list)
                cmd="pt__core__subcmd__help__subcmd__signature__subcmd__list"
                ;;
            pt__core__subcmd__help__subcmd__signature,remove)
                cmd="pt__core__subcmd__help__subcmd__signature__subcmd__remove"
                ;;
            pt__core__subcmd__help__subcmd__signature,show)
                cmd="pt__core__subcmd__help__subcmd__signature__subcmd__show"
                ;;
            pt__core__subcmd__help__subcmd__signature,stats)
                cmd="pt__core__subcmd__help__subcmd__signature__subcmd__stats"
                ;;
            pt__core__subcmd__help__subcmd__signature,test)
                cmd="pt__core__subcmd__help__subcmd__signature__subcmd__test"
                ;;
            pt__core__subcmd__help__subcmd__signature,validate)
                cmd="pt__core__subcmd__help__subcmd__signature__subcmd__validate"
                ;;
            pt__core__subcmd__help__subcmd__telemetry,export)
                cmd="pt__core__subcmd__help__subcmd__telemetry__subcmd__export"
                ;;
            pt__core__subcmd__help__subcmd__telemetry,prune)
                cmd="pt__core__subcmd__help__subcmd__telemetry__subcmd__prune"
                ;;
            pt__core__subcmd__help__subcmd__telemetry,redact)
                cmd="pt__core__subcmd__help__subcmd__telemetry__subcmd__redact"
                ;;
            pt__core__subcmd__help__subcmd__telemetry,status)
                cmd="pt__core__subcmd__help__subcmd__telemetry__subcmd__status"
                ;;
            pt__core__subcmd__help__subcmd__update,list-backups)
                cmd="pt__core__subcmd__help__subcmd__update__subcmd__list__subcmd__backups"
                ;;
            pt__core__subcmd__help__subcmd__update,prune-backups)
                cmd="pt__core__subcmd__help__subcmd__update__subcmd__prune__subcmd__backups"
                ;;
            pt__core__subcmd__help__subcmd__update,rollback)
                cmd="pt__core__subcmd__help__subcmd__update__subcmd__rollback"
                ;;
            pt__core__subcmd__help__subcmd__update,show-backup)
                cmd="pt__core__subcmd__help__subcmd__update__subcmd__show__subcmd__backup"
                ;;
            pt__core__subcmd__help__subcmd__update,verify-backup)
                cmd="pt__core__subcmd__help__subcmd__update__subcmd__verify__subcmd__backup"
                ;;
            pt__core__subcmd__learn,complete)
                cmd="pt__core__subcmd__learn__subcmd__complete"
                ;;
            pt__core__subcmd__learn,help)
                cmd="pt__core__subcmd__learn__subcmd__help"
                ;;
            pt__core__subcmd__learn,list)
                cmd="pt__core__subcmd__learn__subcmd__list"
                ;;
            pt__core__subcmd__learn,reset)
                cmd="pt__core__subcmd__learn__subcmd__reset"
                ;;
            pt__core__subcmd__learn,show)
                cmd="pt__core__subcmd__learn__subcmd__show"
                ;;
            pt__core__subcmd__learn,verify)
                cmd="pt__core__subcmd__learn__subcmd__verify"
                ;;
            pt__core__subcmd__learn__subcmd__help,complete)
                cmd="pt__core__subcmd__learn__subcmd__help__subcmd__complete"
                ;;
            pt__core__subcmd__learn__subcmd__help,help)
                cmd="pt__core__subcmd__learn__subcmd__help__subcmd__help"
                ;;
            pt__core__subcmd__learn__subcmd__help,list)
                cmd="pt__core__subcmd__learn__subcmd__help__subcmd__list"
                ;;
            pt__core__subcmd__learn__subcmd__help,reset)
                cmd="pt__core__subcmd__learn__subcmd__help__subcmd__reset"
                ;;
            pt__core__subcmd__learn__subcmd__help,show)
                cmd="pt__core__subcmd__learn__subcmd__help__subcmd__show"
                ;;
            pt__core__subcmd__learn__subcmd__help,verify)
                cmd="pt__core__subcmd__learn__subcmd__help__subcmd__verify"
                ;;
            pt__core__subcmd__query,actions)
                cmd="pt__core__subcmd__query__subcmd__actions"
                ;;
            pt__core__subcmd__query,help)
                cmd="pt__core__subcmd__query__subcmd__help"
                ;;
            pt__core__subcmd__query,sessions)
                cmd="pt__core__subcmd__query__subcmd__sessions"
                ;;
            pt__core__subcmd__query,telemetry)
                cmd="pt__core__subcmd__query__subcmd__telemetry"
                ;;
            pt__core__subcmd__query__subcmd__help,actions)
                cmd="pt__core__subcmd__query__subcmd__help__subcmd__actions"
                ;;
            pt__core__subcmd__query__subcmd__help,help)
                cmd="pt__core__subcmd__query__subcmd__help__subcmd__help"
                ;;
            pt__core__subcmd__query__subcmd__help,sessions)
                cmd="pt__core__subcmd__query__subcmd__help__subcmd__sessions"
                ;;
            pt__core__subcmd__query__subcmd__help,telemetry)
                cmd="pt__core__subcmd__query__subcmd__help__subcmd__telemetry"
                ;;
            pt__core__subcmd__replay,evaluate)
                cmd="pt__core__subcmd__replay__subcmd__evaluate"
                ;;
            pt__core__subcmd__replay,help)
                cmd="pt__core__subcmd__replay__subcmd__help"
                ;;
            pt__core__subcmd__replay,label-template)
                cmd="pt__core__subcmd__replay__subcmd__label__subcmd__template"
                ;;
            pt__core__subcmd__replay,refit)
                cmd="pt__core__subcmd__replay__subcmd__refit"
                ;;
            pt__core__subcmd__replay__subcmd__help,evaluate)
                cmd="pt__core__subcmd__replay__subcmd__help__subcmd__evaluate"
                ;;
            pt__core__subcmd__replay__subcmd__help,help)
                cmd="pt__core__subcmd__replay__subcmd__help__subcmd__help"
                ;;
            pt__core__subcmd__replay__subcmd__help,label-template)
                cmd="pt__core__subcmd__replay__subcmd__help__subcmd__label__subcmd__template"
                ;;
            pt__core__subcmd__replay__subcmd__help,refit)
                cmd="pt__core__subcmd__replay__subcmd__help__subcmd__refit"
                ;;
            pt__core__subcmd__shadow,export)
                cmd="pt__core__subcmd__shadow__subcmd__export"
                ;;
            pt__core__subcmd__shadow,help)
                cmd="pt__core__subcmd__shadow__subcmd__help"
                ;;
            pt__core__subcmd__shadow,report)
                cmd="pt__core__subcmd__shadow__subcmd__report"
                ;;
            pt__core__subcmd__shadow,run)
                cmd="pt__core__subcmd__shadow__subcmd__run"
                ;;
            pt__core__subcmd__shadow,start)
                cmd="pt__core__subcmd__shadow__subcmd__start"
                ;;
            pt__core__subcmd__shadow,status)
                cmd="pt__core__subcmd__shadow__subcmd__status"
                ;;
            pt__core__subcmd__shadow,stop)
                cmd="pt__core__subcmd__shadow__subcmd__stop"
                ;;
            pt__core__subcmd__shadow__subcmd__help,export)
                cmd="pt__core__subcmd__shadow__subcmd__help__subcmd__export"
                ;;
            pt__core__subcmd__shadow__subcmd__help,help)
                cmd="pt__core__subcmd__shadow__subcmd__help__subcmd__help"
                ;;
            pt__core__subcmd__shadow__subcmd__help,report)
                cmd="pt__core__subcmd__shadow__subcmd__help__subcmd__report"
                ;;
            pt__core__subcmd__shadow__subcmd__help,run)
                cmd="pt__core__subcmd__shadow__subcmd__help__subcmd__run"
                ;;
            pt__core__subcmd__shadow__subcmd__help,start)
                cmd="pt__core__subcmd__shadow__subcmd__help__subcmd__start"
                ;;
            pt__core__subcmd__shadow__subcmd__help,status)
                cmd="pt__core__subcmd__shadow__subcmd__help__subcmd__status"
                ;;
            pt__core__subcmd__shadow__subcmd__help,stop)
                cmd="pt__core__subcmd__shadow__subcmd__help__subcmd__stop"
                ;;
            pt__core__subcmd__signature,add)
                cmd="pt__core__subcmd__signature__subcmd__add"
                ;;
            pt__core__subcmd__signature,disable)
                cmd="pt__core__subcmd__signature__subcmd__disable"
                ;;
            pt__core__subcmd__signature,enable)
                cmd="pt__core__subcmd__signature__subcmd__enable"
                ;;
            pt__core__subcmd__signature,export)
                cmd="pt__core__subcmd__signature__subcmd__export"
                ;;
            pt__core__subcmd__signature,help)
                cmd="pt__core__subcmd__signature__subcmd__help"
                ;;
            pt__core__subcmd__signature,import)
                cmd="pt__core__subcmd__signature__subcmd__import"
                ;;
            pt__core__subcmd__signature,list)
                cmd="pt__core__subcmd__signature__subcmd__list"
                ;;
            pt__core__subcmd__signature,remove)
                cmd="pt__core__subcmd__signature__subcmd__remove"
                ;;
            pt__core__subcmd__signature,show)
                cmd="pt__core__subcmd__signature__subcmd__show"
                ;;
            pt__core__subcmd__signature,stats)
                cmd="pt__core__subcmd__signature__subcmd__stats"
                ;;
            pt__core__subcmd__signature,test)
                cmd="pt__core__subcmd__signature__subcmd__test"
                ;;
            pt__core__subcmd__signature,validate)
                cmd="pt__core__subcmd__signature__subcmd__validate"
                ;;
            pt__core__subcmd__signature__subcmd__help,add)
                cmd="pt__core__subcmd__signature__subcmd__help__subcmd__add"
                ;;
            pt__core__subcmd__signature__subcmd__help,disable)
                cmd="pt__core__subcmd__signature__subcmd__help__subcmd__disable"
                ;;
            pt__core__subcmd__signature__subcmd__help,enable)
                cmd="pt__core__subcmd__signature__subcmd__help__subcmd__enable"
                ;;
            pt__core__subcmd__signature__subcmd__help,export)
                cmd="pt__core__subcmd__signature__subcmd__help__subcmd__export"
                ;;
            pt__core__subcmd__signature__subcmd__help,help)
                cmd="pt__core__subcmd__signature__subcmd__help__subcmd__help"
                ;;
            pt__core__subcmd__signature__subcmd__help,import)
                cmd="pt__core__subcmd__signature__subcmd__help__subcmd__import"
                ;;
            pt__core__subcmd__signature__subcmd__help,list)
                cmd="pt__core__subcmd__signature__subcmd__help__subcmd__list"
                ;;
            pt__core__subcmd__signature__subcmd__help,remove)
                cmd="pt__core__subcmd__signature__subcmd__help__subcmd__remove"
                ;;
            pt__core__subcmd__signature__subcmd__help,show)
                cmd="pt__core__subcmd__signature__subcmd__help__subcmd__show"
                ;;
            pt__core__subcmd__signature__subcmd__help,stats)
                cmd="pt__core__subcmd__signature__subcmd__help__subcmd__stats"
                ;;
            pt__core__subcmd__signature__subcmd__help,test)
                cmd="pt__core__subcmd__signature__subcmd__help__subcmd__test"
                ;;
            pt__core__subcmd__signature__subcmd__help,validate)
                cmd="pt__core__subcmd__signature__subcmd__help__subcmd__validate"
                ;;
            pt__core__subcmd__telemetry,export)
                cmd="pt__core__subcmd__telemetry__subcmd__export"
                ;;
            pt__core__subcmd__telemetry,help)
                cmd="pt__core__subcmd__telemetry__subcmd__help"
                ;;
            pt__core__subcmd__telemetry,prune)
                cmd="pt__core__subcmd__telemetry__subcmd__prune"
                ;;
            pt__core__subcmd__telemetry,redact)
                cmd="pt__core__subcmd__telemetry__subcmd__redact"
                ;;
            pt__core__subcmd__telemetry,status)
                cmd="pt__core__subcmd__telemetry__subcmd__status"
                ;;
            pt__core__subcmd__telemetry__subcmd__help,export)
                cmd="pt__core__subcmd__telemetry__subcmd__help__subcmd__export"
                ;;
            pt__core__subcmd__telemetry__subcmd__help,help)
                cmd="pt__core__subcmd__telemetry__subcmd__help__subcmd__help"
                ;;
            pt__core__subcmd__telemetry__subcmd__help,prune)
                cmd="pt__core__subcmd__telemetry__subcmd__help__subcmd__prune"
                ;;
            pt__core__subcmd__telemetry__subcmd__help,redact)
                cmd="pt__core__subcmd__telemetry__subcmd__help__subcmd__redact"
                ;;
            pt__core__subcmd__telemetry__subcmd__help,status)
                cmd="pt__core__subcmd__telemetry__subcmd__help__subcmd__status"
                ;;
            pt__core__subcmd__update,help)
                cmd="pt__core__subcmd__update__subcmd__help"
                ;;
            pt__core__subcmd__update,list-backups)
                cmd="pt__core__subcmd__update__subcmd__list__subcmd__backups"
                ;;
            pt__core__subcmd__update,prune-backups)
                cmd="pt__core__subcmd__update__subcmd__prune__subcmd__backups"
                ;;
            pt__core__subcmd__update,rollback)
                cmd="pt__core__subcmd__update__subcmd__rollback"
                ;;
            pt__core__subcmd__update,show-backup)
                cmd="pt__core__subcmd__update__subcmd__show__subcmd__backup"
                ;;
            pt__core__subcmd__update,verify-backup)
                cmd="pt__core__subcmd__update__subcmd__verify__subcmd__backup"
                ;;
            pt__core__subcmd__update__subcmd__help,help)
                cmd="pt__core__subcmd__update__subcmd__help__subcmd__help"
                ;;
            pt__core__subcmd__update__subcmd__help,list-backups)
                cmd="pt__core__subcmd__update__subcmd__help__subcmd__list__subcmd__backups"
                ;;
            pt__core__subcmd__update__subcmd__help,prune-backups)
                cmd="pt__core__subcmd__update__subcmd__help__subcmd__prune__subcmd__backups"
                ;;
            pt__core__subcmd__update__subcmd__help,rollback)
                cmd="pt__core__subcmd__update__subcmd__help__subcmd__rollback"
                ;;
            pt__core__subcmd__update__subcmd__help,show-backup)
                cmd="pt__core__subcmd__update__subcmd__help__subcmd__show__subcmd__backup"
                ;;
            pt__core__subcmd__update__subcmd__help,verify-backup)
                cmd="pt__core__subcmd__update__subcmd__help__subcmd__verify__subcmd__backup"
                ;;
            *)
                ;;
        esac
    done

    case "${cmd}" in
        pt__core)
            opts="-f -v -q -h -V --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version run scan replay deep-scan __deep-scan-worker diff query bundle report check doctor learn agent robot config daemon telemetry shadow signature schema update mcp completions version help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 1 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd____deep__subcmd__scan__subcmd__worker)
            opts="-f -v -q -h -V --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent)
            opts="-f -v -q -h -V --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__apply)
            opts="-f -v -q -h -V --session --pids --targets --yes --recommended --min-age --min-posterior --max-blast-radius --max-total-blast-radius --max-kills --require-known-signature --only-categories --exclude-categories --abort-on-unknown --resume --settle --expected-host-id --expected-plan-sha256 --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --session)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --pids)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --targets)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --min-age)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --min-posterior)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-blast-radius)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-total-blast-radius)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-kills)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --only-categories)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --exclude-categories)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --settle)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --expected-host-id)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --expected-plan-sha256)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__capabilities)
            opts="-f -v -q -h -V --check-action --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --check-action)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__diff)
            opts="-f -v -q -h -V --base --compare --focus --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --base)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --compare)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --focus)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__explain)
            opts="-f -v -q -h -V --session --pids --target --live --window-ms --include --galaxy-brain --show-dependencies --show-blast-radius --show-history --what-if --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --session)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --pids)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --target)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --window-ms)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --include)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__export)
            opts="-o -f -v -q -h -V --session --out --profile --include-telemetry --include-dumps --encrypt --passphrase --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --session)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --out)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -o)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --passphrase)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__export__subcmd__priors)
            opts="-o -f -v -q -h -V --out --host-profile --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --out)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -o)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --host-profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__fleet)
            opts="-f -v -q -h -V --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version inventory health doctor plan apply report status transfer help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__fleet__subcmd__apply)
            opts="-f -v -q -h -V --fleet-session --confirm --parallel --timeout --max-kills-per-host --continue-on-error --capabilities --config --format --verbose --quiet --no-color --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --fleet-session)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --parallel)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-kills-per-host)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__fleet__subcmd__doctor)
            opts="-f -v -q -h -V --hosts --inventory --discovery-config --ssh-config --host-filter --parallel --timeout --connect-timeout --max-consecutive-failures --remote-binary --capabilities --config --format --verbose --quiet --no-color --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --hosts)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --inventory)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --discovery-config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --ssh-config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --host-filter)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --parallel)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --connect-timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-consecutive-failures)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --remote-binary)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__fleet__subcmd__health)
            opts="-f -v -q -h -V --hosts --inventory --discovery-config --ssh-config --host-filter --parallel --timeout --connect-timeout --max-consecutive-failures --remote-binary --capabilities --config --format --verbose --quiet --no-color --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --hosts)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --inventory)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --discovery-config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --ssh-config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --host-filter)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --parallel)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --connect-timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-consecutive-failures)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --remote-binary)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__fleet__subcmd__help)
            opts="inventory health doctor plan apply report status transfer help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__fleet__subcmd__help__subcmd__apply)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__fleet__subcmd__help__subcmd__doctor)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__fleet__subcmd__help__subcmd__health)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__fleet__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__fleet__subcmd__help__subcmd__inventory)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__fleet__subcmd__help__subcmd__plan)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__fleet__subcmd__help__subcmd__report)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__fleet__subcmd__help__subcmd__status)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__fleet__subcmd__help__subcmd__transfer)
            opts="export import diff"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__fleet__subcmd__help__subcmd__transfer__subcmd__diff)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 6 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__fleet__subcmd__help__subcmd__transfer__subcmd__export)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 6 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__fleet__subcmd__help__subcmd__transfer__subcmd__import)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 6 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__fleet__subcmd__inventory)
            opts="-f -v -q -h -V --hosts --inventory --discovery-config --ssh-config --host-filter --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --hosts)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --inventory)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --discovery-config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --ssh-config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --host-filter)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__fleet__subcmd__plan)
            opts="-f -v -q -h -V --hosts --inventory --discovery-config --ssh-config --host-filter --parallel --timeout --remote-binary --continue-on-error --goal --min-age --min-posterior --window-ms --max-candidates --host-profile --label --max-fdr --capabilities --config --format --verbose --quiet --no-color --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --hosts)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --inventory)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --discovery-config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --ssh-config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --host-filter)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --parallel)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --remote-binary)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --goal)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --min-age)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --min-posterior)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --window-ms)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-candidates)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --host-profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --label)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-fdr)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__fleet__subcmd__report)
            opts="-f -v -q -h -V --fleet-session --out --profile --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --fleet-session)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --out)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__fleet__subcmd__status)
            opts="-f -v -q -h -V --fleet-session --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --fleet-session)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__fleet__subcmd__transfer)
            opts="-f -v -q -h -V --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version export import diff help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__fleet__subcmd__transfer__subcmd__diff)
            opts="-f -v -q -h -V --from --passphrase --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --passphrase)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__fleet__subcmd__transfer__subcmd__export)
            opts="-o -f -v -q -h -V --out --host-profile --include-signatures --include-priors --export-profile --passphrase --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --out)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -o)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --host-profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --export-profile)
                    COMPREPLY=($(compgen -W "minimal safe forensic" -- "${cur}"))
                    return 0
                    ;;
                --passphrase)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__fleet__subcmd__transfer__subcmd__help)
            opts="export import diff help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__fleet__subcmd__transfer__subcmd__help__subcmd__diff)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 6 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__fleet__subcmd__transfer__subcmd__help__subcmd__export)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 6 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__fleet__subcmd__transfer__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 6 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__fleet__subcmd__transfer__subcmd__help__subcmd__import)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 6 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__fleet__subcmd__transfer__subcmd__import)
            opts="-f -v -q -h -V --from --merge-strategy --dry-run --no-backup --passphrase --normalize-baseline --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --merge-strategy)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --passphrase)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__help)
            opts="plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__help__subcmd__apply)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__help__subcmd__capabilities)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__help__subcmd__diff)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__help__subcmd__explain)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__help__subcmd__export)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__help__subcmd__export__subcmd__priors)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__help__subcmd__fleet)
            opts="inventory health doctor plan apply report status transfer"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__help__subcmd__fleet__subcmd__apply)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__help__subcmd__fleet__subcmd__doctor)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__help__subcmd__fleet__subcmd__health)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__help__subcmd__fleet__subcmd__inventory)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__help__subcmd__fleet__subcmd__plan)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__help__subcmd__fleet__subcmd__report)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__help__subcmd__fleet__subcmd__status)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__help__subcmd__fleet__subcmd__transfer)
            opts="export import diff"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__help__subcmd__fleet__subcmd__transfer__subcmd__diff)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 6 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__help__subcmd__fleet__subcmd__transfer__subcmd__export)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 6 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__help__subcmd__fleet__subcmd__transfer__subcmd__import)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 6 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__help__subcmd__import__subcmd__priors)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__help__subcmd__inbox)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__help__subcmd__init)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__help__subcmd__label)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__help__subcmd__list__subcmd__priors)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__help__subcmd__plan)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__help__subcmd__report)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__help__subcmd__sessions)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__help__subcmd__snapshot)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__help__subcmd__tail)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__help__subcmd__undo)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__help__subcmd__verify)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__help__subcmd__watch)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__import__subcmd__priors)
            opts="-i -f -v -q -h -V --from --merge --replace --host-profile --dry-run --no-backup --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -i)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --host-profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__inbox)
            opts="-f -v -q -h -V --ack --clear --clear-all --unread --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --ack)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__init)
            opts="-f -v -q -h -V --yes --dry-run --agent --skip-backup --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --agent)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__label)
            opts="-f -v -q -h -V --pid --session --cmd --comm --kill --spare --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --pid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --session)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cmd)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --comm)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__list__subcmd__priors)
            opts="-f -v -q -h -V --class --extended --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --class)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__plan)
            opts="-f -v -q -h -V --session --label --max-candidates --pids --threshold --min-posterior --only --yes --include-kernel-threads --deep --probe-budget-ms --window-ms --min-age --sample-size --include-predictions --prediction-fields --since --since-time --goal --minimal --pretty --brief --narrative --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --session)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --label)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-candidates)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --pids)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --min-posterior)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --threshold)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --only)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --probe-budget-ms)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --window-ms)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --min-age)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --sample-size)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --prediction-fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --since)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --since-time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --goal)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__report)
            opts="-o -f -v -q -h -V --session --bundle --passphrase --out --profile --galaxy-brain --embed-assets --report-format --prose-style --title --theme --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --session)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --bundle)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --passphrase)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --out)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -o)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --report-format)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --prose-style)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --title)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --theme)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__sessions)
            opts="-f -v -q -h -V --session --detail --limit --state --cleanup --yes --older-than --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --session)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --limit)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --state)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --older-than)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__snapshot)
            opts="-f -v -q -h -V --label --top --window-ms --include-env --include-network --minimal --pretty --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --label)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --top)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --window-ms)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__tail)
            opts="-f -v -q -h -V --session --follow --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --session)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__undo)
            opts="-f -v -q -h -V --session --action-id --all --attempt-id --confirm --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --session)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --action-id)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --attempt-id)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__verify)
            opts="-f -v -q -h -V --session --wait --check-respawn --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --session)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --wait)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__agent__subcmd__watch)
            opts="-f -v -q -h -V --notify-exec --notify-cmd --notify-arg --threshold --interval --min-age --window-ms --once --goal-memory-available-gb --goal-load-max --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --notify-exec)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --notify-cmd)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --notify-arg)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --threshold)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --interval)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --min-age)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --window-ms)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --goal-memory-available-gb)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --goal-load-max)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__bundle)
            opts="-f -v -q -h -V --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version create inspect extract help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__bundle__subcmd__create)
            opts="-o -f -v -q -h -V --session --output --profile --include-telemetry --include-dumps --encrypt --passphrase --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --session)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -o)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --passphrase)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__bundle__subcmd__extract)
            opts="-o -f -v -q -h -V --output --verify --passphrase --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -o)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --passphrase)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__bundle__subcmd__help)
            opts="create inspect extract help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__bundle__subcmd__help__subcmd__create)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__bundle__subcmd__help__subcmd__extract)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__bundle__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__bundle__subcmd__help__subcmd__inspect)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__bundle__subcmd__inspect)
            opts="-f -v -q -h -V --verify --passphrase --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --passphrase)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__check)
            opts="-f -v -q -h -V --priors --policy --check-capabilities --all --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__completions)
            opts="-f -v -q -h -V --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version bash elvish fish powershell zsh"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__config)
            opts="-f -v -q -h -V --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version show schema validate list-presets show-preset diff-preset export-preset help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__config__subcmd__diff__subcmd__preset)
            opts="-f -v -q -h -V --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__config__subcmd__export__subcmd__preset)
            opts="-o -f -v -q -h -V --output --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -o)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__config__subcmd__help)
            opts="show schema validate list-presets show-preset diff-preset export-preset help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__config__subcmd__help__subcmd__diff__subcmd__preset)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__config__subcmd__help__subcmd__export__subcmd__preset)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__config__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__config__subcmd__help__subcmd__list__subcmd__presets)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__config__subcmd__help__subcmd__schema)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__config__subcmd__help__subcmd__show)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__config__subcmd__help__subcmd__show__subcmd__preset)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__config__subcmd__help__subcmd__validate)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__config__subcmd__list__subcmd__presets)
            opts="-f -v -q -h -V --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__config__subcmd__schema)
            opts="-f -v -q -h -V --file --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__config__subcmd__show)
            opts="-f -v -q -h -V --file --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__config__subcmd__show__subcmd__preset)
            opts="-f -v -q -h -V --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__config__subcmd__validate)
            opts="-f -v -q -h -V --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__daemon)
            opts="-f -v -q -h -V --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version start stop status install service-status uninstall help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__daemon__subcmd__help)
            opts="start stop status install service-status uninstall help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__daemon__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__daemon__subcmd__help__subcmd__install)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__daemon__subcmd__help__subcmd__service__subcmd__status)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__daemon__subcmd__help__subcmd__start)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__daemon__subcmd__help__subcmd__status)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__daemon__subcmd__help__subcmd__stop)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__daemon__subcmd__help__subcmd__uninstall)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__daemon__subcmd__install)
            opts="-f -v -q -h -V --activate --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__daemon__subcmd__service__subcmd__status)
            opts="-f -v -q -h -V --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__daemon__subcmd__start)
            opts="-f -v -q -h -V --foreground --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__daemon__subcmd__status)
            opts="-f -v -q -h -V --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__daemon__subcmd__stop)
            opts="-f -v -q -h -V --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__daemon__subcmd__uninstall)
            opts="-f -v -q -h -V --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__deep__subcmd__scan)
            opts="-f -v -q -h -V --pids --budget --allow-partial --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --pids)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --budget)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__diff)
            opts="-f -v -q -h -V --baseline --last --changed-only --category --min-score-delta --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --category)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --min-score-delta)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__doctor)
            opts="-f -v -q -h -V --fix-script --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help)
            opts="run scan replay deep-scan __deep-scan-worker diff query bundle report check doctor learn agent config daemon telemetry shadow signature schema update mcp completions version help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd____deep__subcmd__scan__subcmd__worker)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__agent)
            opts="plan explain apply undo verify diff snapshot capabilities sessions list-priors label inbox tail watch export-priors import-priors report init export fleet"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__agent__subcmd__apply)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__agent__subcmd__capabilities)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__agent__subcmd__diff)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__agent__subcmd__explain)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__agent__subcmd__export)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__agent__subcmd__export__subcmd__priors)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__agent__subcmd__fleet)
            opts="inventory health doctor plan apply report status transfer"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__agent__subcmd__fleet__subcmd__apply)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__agent__subcmd__fleet__subcmd__doctor)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__agent__subcmd__fleet__subcmd__health)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__agent__subcmd__fleet__subcmd__inventory)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__agent__subcmd__fleet__subcmd__plan)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__agent__subcmd__fleet__subcmd__report)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__agent__subcmd__fleet__subcmd__status)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__agent__subcmd__fleet__subcmd__transfer)
            opts="export import diff"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__agent__subcmd__fleet__subcmd__transfer__subcmd__diff)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 6 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__agent__subcmd__fleet__subcmd__transfer__subcmd__export)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 6 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__agent__subcmd__fleet__subcmd__transfer__subcmd__import)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 6 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__agent__subcmd__import__subcmd__priors)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__agent__subcmd__inbox)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__agent__subcmd__init)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__agent__subcmd__label)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__agent__subcmd__list__subcmd__priors)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__agent__subcmd__plan)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__agent__subcmd__report)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__agent__subcmd__sessions)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__agent__subcmd__snapshot)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__agent__subcmd__tail)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__agent__subcmd__undo)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__agent__subcmd__verify)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__agent__subcmd__watch)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__bundle)
            opts="create inspect extract"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__bundle__subcmd__create)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__bundle__subcmd__extract)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__bundle__subcmd__inspect)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__check)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__completions)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__config)
            opts="show schema validate list-presets show-preset diff-preset export-preset"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__config__subcmd__diff__subcmd__preset)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__config__subcmd__export__subcmd__preset)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__config__subcmd__list__subcmd__presets)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__config__subcmd__schema)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__config__subcmd__show)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__config__subcmd__show__subcmd__preset)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__config__subcmd__validate)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__daemon)
            opts="start stop status install service-status uninstall"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__daemon__subcmd__install)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__daemon__subcmd__service__subcmd__status)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__daemon__subcmd__start)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__daemon__subcmd__status)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__daemon__subcmd__stop)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__daemon__subcmd__uninstall)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__deep__subcmd__scan)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__diff)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__doctor)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__learn)
            opts="list show verify complete reset"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__learn__subcmd__complete)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__learn__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__learn__subcmd__reset)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__learn__subcmd__show)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__learn__subcmd__verify)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__mcp)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__query)
            opts="sessions actions telemetry"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__query__subcmd__actions)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__query__subcmd__sessions)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__query__subcmd__telemetry)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__replay)
            opts="label-template evaluate refit"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__replay__subcmd__evaluate)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__replay__subcmd__label__subcmd__template)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__replay__subcmd__refit)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__report)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__run)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__scan)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__schema)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__shadow)
            opts="start run stop status export report"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__shadow__subcmd__export)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__shadow__subcmd__report)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__shadow__subcmd__run)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__shadow__subcmd__start)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__shadow__subcmd__status)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__shadow__subcmd__stop)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__signature)
            opts="list show add remove test validate export disable enable import stats"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__signature__subcmd__add)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__signature__subcmd__disable)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__signature__subcmd__enable)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__signature__subcmd__export)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__signature__subcmd__import)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__signature__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__signature__subcmd__remove)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__signature__subcmd__show)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__signature__subcmd__stats)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__signature__subcmd__test)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__signature__subcmd__validate)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__telemetry)
            opts="status export prune redact"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__telemetry__subcmd__export)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__telemetry__subcmd__prune)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__telemetry__subcmd__redact)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__telemetry__subcmd__status)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__update)
            opts="rollback list-backups show-backup verify-backup prune-backups"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__update__subcmd__list__subcmd__backups)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__update__subcmd__prune__subcmd__backups)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__update__subcmd__rollback)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__update__subcmd__show__subcmd__backup)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__update__subcmd__verify__subcmd__backup)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__help__subcmd__version)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__learn)
            opts="-f -v -q -h -V --verify-budget-ms --total-budget-ms --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version list show verify complete reset help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --verify-budget-ms)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --total-budget-ms)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__learn__subcmd__complete)
            opts="-f -v -q -h -V --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__learn__subcmd__help)
            opts="list show verify complete reset help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__learn__subcmd__help__subcmd__complete)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__learn__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__learn__subcmd__help__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__learn__subcmd__help__subcmd__reset)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__learn__subcmd__help__subcmd__show)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__learn__subcmd__help__subcmd__verify)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__learn__subcmd__list)
            opts="-f -v -q -h -V --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__learn__subcmd__reset)
            opts="-f -v -q -h -V --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__learn__subcmd__show)
            opts="-f -v -q -h -V --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__learn__subcmd__verify)
            opts="-f -v -q -h -V --all --mark-complete --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__mcp)
            opts="-f -v -q -h -V --transport --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --transport)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__query)
            opts="-f -v -q -h -V --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version sessions actions telemetry help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__query__subcmd__actions)
            opts="-f -v -q -h -V --session --limit --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --session)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --limit)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__query__subcmd__help)
            opts="sessions actions telemetry help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__query__subcmd__help__subcmd__actions)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__query__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__query__subcmd__help__subcmd__sessions)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__query__subcmd__help__subcmd__telemetry)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__query__subcmd__sessions)
            opts="-f -v -q -h -V --limit --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --limit)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__query__subcmd__telemetry)
            opts="-f -v -q -h -V --range --table --session --limit --telemetry-dir --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --range)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --table)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --session)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --limit)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --telemetry-dir)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__replay)
            opts="-f -v -q -h -V --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version label-template evaluate refit help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__replay__subcmd__evaluate)
            opts="-f -v -q -h -V --snapshot --labels --baseline-config --top-k --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --snapshot)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --labels)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --baseline-config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --top-k)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__replay__subcmd__help)
            opts="label-template evaluate refit help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__replay__subcmd__help__subcmd__evaluate)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__replay__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__replay__subcmd__help__subcmd__label__subcmd__template)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__replay__subcmd__help__subcmd__refit)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__replay__subcmd__label__subcmd__template)
            opts="-f -v -q -h -V --snapshot --output --host-id --split --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --snapshot)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --host-id)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --split)
                    COMPREPLY=($(compgen -W "training holdout" -- "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__replay__subcmd__refit)
            opts="-f -v -q -h -V --training-snapshot --training-labels --holdout-snapshot --snapshot --holdout-labels --labels --output --method --max-change-fraction --grid-points --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --training-snapshot)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --training-labels)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --snapshot)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --holdout-snapshot)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --labels)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --holdout-labels)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --method)
                    COMPREPLY=($(compgen -W "counts score-grid" -- "${cur}"))
                    return 0
                    ;;
                --max-change-fraction)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --grid-points)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__report)
            opts="-o -f -v -q -h -V --session --bundle --passphrase --output --include-ledger --embed-assets --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --session)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --bundle)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --passphrase)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -o)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__run)
            opts="-f -v -q -h -V --deep --probe-budget-ms --window-ms --inline --signatures --community-signatures --min-age --threshold --min-posterior --goal --theme --high-contrast --reduce-motion --accessible --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --probe-budget-ms)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --window-ms)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --signatures)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --min-age)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --min-posterior)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --threshold)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --goal)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --theme)
                    COMPREPLY=($(compgen -W "dark light high-contrast no-color" -- "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__scan)
            opts="-f -v -q -h -V --deep --samples --interval --include-kernel-threads --goal --record-replay --record-replay-window-ms --replay-scores --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --samples)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --interval)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --goal)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --record-replay)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --record-replay-window-ms)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --replay-scores)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__schema)
            opts="-l -a -f -v -q -h -V --list --all --compact --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__shadow)
            opts="-f -v -q -h -V --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version start run stop status export report help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__shadow__subcmd__export)
            opts="-o -f -v -q -h -V --output --export-format --limit --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -o)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --export-format)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --limit)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__shadow__subcmd__help)
            opts="start run stop status export report help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__shadow__subcmd__help__subcmd__export)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__shadow__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__shadow__subcmd__help__subcmd__report)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__shadow__subcmd__help__subcmd__run)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__shadow__subcmd__help__subcmd__start)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__shadow__subcmd__help__subcmd__status)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__shadow__subcmd__help__subcmd__stop)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__shadow__subcmd__report)
            opts="-o -f -v -q -h -V --output --threshold --limit --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -o)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --threshold)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --limit)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__shadow__subcmd__run)
            opts="-f -v -q -h -V --interval --deep-interval --iterations --background --max-candidates --min-posterior --only --include-kernel-threads --deep --min-age --sample-size --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --interval)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --deep-interval)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --iterations)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-candidates)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --min-posterior)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --only)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --min-age)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --sample-size)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__shadow__subcmd__start)
            opts="-f -v -q -h -V --interval --deep-interval --iterations --background --max-candidates --min-posterior --only --include-kernel-threads --deep --min-age --sample-size --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --interval)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --deep-interval)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --iterations)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-candidates)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --min-posterior)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --only)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --min-age)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --sample-size)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__shadow__subcmd__status)
            opts="-f -v -q -h -V --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__shadow__subcmd__stop)
            opts="-f -v -q -h -V --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__signature)
            opts="-f -v -q -h -V --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version list show add remove test validate export disable enable import stats help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__signature__subcmd__add)
            opts="-f -v -q -h -V --category --pattern --arg-pattern --env-var --confidence --notes --priority --prior --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --category)
                    COMPREPLY=($(compgen -W "agent ide ci orchestrator terminal other" -- "${cur}"))
                    return 0
                    ;;
                --pattern)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --arg-pattern)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --env-var)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --confidence)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --notes)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --priority)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --prior)
                    COMPREPLY=($(compgen -W "useful abandoned" -- "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__signature__subcmd__disable)
            opts="-f -v -q -h -V --reason --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --reason)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__signature__subcmd__enable)
            opts="-f -v -q -h -V --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__signature__subcmd__export)
            opts="-f -v -q -h -V --user-only --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__signature__subcmd__help)
            opts="list show add remove test validate export disable enable import stats help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__signature__subcmd__help__subcmd__add)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__signature__subcmd__help__subcmd__disable)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__signature__subcmd__help__subcmd__enable)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__signature__subcmd__help__subcmd__export)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__signature__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__signature__subcmd__help__subcmd__import)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__signature__subcmd__help__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__signature__subcmd__help__subcmd__remove)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__signature__subcmd__help__subcmd__show)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__signature__subcmd__help__subcmd__stats)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__signature__subcmd__help__subcmd__test)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__signature__subcmd__help__subcmd__validate)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__signature__subcmd__import)
            opts="-f -v -q -h -V --dry-run --passphrase --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --passphrase)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__signature__subcmd__list)
            opts="-f -v -q -h -V --user-only --builtin-only --category --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --category)
                    COMPREPLY=($(compgen -W "agent ide ci orchestrator terminal other" -- "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__signature__subcmd__remove)
            opts="-f -v -q -h -V --force --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__signature__subcmd__show)
            opts="-f -v -q -h -V --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__signature__subcmd__stats)
            opts="-f -v -q -h -V --min-matches --sort --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --min-matches)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --sort)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__signature__subcmd__test)
            opts="-f -v -q -h -V --cmdline --all --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cmdline)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__signature__subcmd__validate)
            opts="-f -v -q -h -V --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__telemetry)
            opts="-f -v -q -h -V --telemetry-dir --retention-config --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version status export prune redact help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --telemetry-dir)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --retention-config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__telemetry__subcmd__export)
            opts="-o -f -v -q -h -V --output --export-format --table --range --session --telemetry-dir --retention-config --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -o)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --export-format)
                    COMPREPLY=($(compgen -W "parquet csv json jsonl" -- "${cur}"))
                    return 0
                    ;;
                --table)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --range)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --session)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --telemetry-dir)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --retention-config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__telemetry__subcmd__help)
            opts="status export prune redact help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__telemetry__subcmd__help__subcmd__export)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__telemetry__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__telemetry__subcmd__help__subcmd__prune)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__telemetry__subcmd__help__subcmd__redact)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__telemetry__subcmd__help__subcmd__status)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__telemetry__subcmd__prune)
            opts="-f -v -q -h -V --keep --dry-run --keep-everything --telemetry-dir --retention-config --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --keep)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --telemetry-dir)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --retention-config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__telemetry__subcmd__redact)
            opts="-o -f -v -q -h -V --all --output --profile --telemetry-dir --retention-config --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -o)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -W "safe minimal" -- "${cur}"))
                    return 0
                    ;;
                --telemetry-dir)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --retention-config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__telemetry__subcmd__status)
            opts="-f -v -q -h -V --telemetry-dir --retention-config --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --telemetry-dir)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --retention-config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__update)
            opts="-f -v -q -h -V --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version rollback list-backups show-backup verify-backup prune-backups help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__update__subcmd__help)
            opts="rollback list-backups show-backup verify-backup prune-backups help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__update__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__update__subcmd__help__subcmd__list__subcmd__backups)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__update__subcmd__help__subcmd__prune__subcmd__backups)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__update__subcmd__help__subcmd__rollback)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__update__subcmd__help__subcmd__show__subcmd__backup)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__update__subcmd__help__subcmd__verify__subcmd__backup)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__update__subcmd__list__subcmd__backups)
            opts="-f -v -q -h -V --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__update__subcmd__prune__subcmd__backups)
            opts="-f -v -q -h -V --keep --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --keep)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__update__subcmd__rollback)
            opts="-f -v -q -h -V --force --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__update__subcmd__show__subcmd__backup)
            opts="-f -v -q -h -V --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__update__subcmd__verify__subcmd__backup)
            opts="-f -v -q -h -V --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        pt__subcmd__core__subcmd__version)
            opts="-f -v -q -h -V --capabilities --config --format --verbose --quiet --no-color --timeout --robot --shadow --dry-run --standalone --fields --compact --max-tokens --estimate-tokens --help --version"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --capabilities)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "json toon md jsonl summary metrics slack exitcode prose" -- "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fields)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-tokens)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
    esac
}

if [[ "${BASH_VERSINFO[0]}" -eq 4 && "${BASH_VERSINFO[1]}" -ge 4 || "${BASH_VERSINFO[0]}" -gt 4 ]]; then
    complete -F _pt__core -o nosort -o bashdefault -o default pt-core
else
    complete -F _pt__core -o bashdefault -o default pt-core
fi
