-- workspace: 工作环境
workspace "InlineHook" -- Visual Studio中的解决方案
    location "../build" -- 解决方案文件夹
    objdir "../build/obj" -- obj目录
    system "android"
    language "C++"
    cdialect "C11"
    cppdialect "C++latest"
    characterset "MBCS"
    staticruntime "On"
    toolset "clang"
    kind "StaticLib" --编译为静态库
    targetdir "../Library" -- 生成的目标文件的路径
    
    configurations { -- 解决方案配置项, 默认的配置
        "Debug", 
        "Release" 
    }

    platforms { -- 设置平台
        "ARM",
        "ARM64"
    }
    
    filter "configurations:Debug" -- debug模式的设置
        defines { "DEBUG" }
        symbols "On"
        optimize "Off"

    filter "configurations:Release" -- release模式的设置
        defines { "NDEBUG", "ANDROID" }
        symbols "Off"
        optimize "Full"
        
project "CydiaSubstrateInlineHook" -- 项目名称
    architecture "ARM"

    files { -- 项目文件
        "../Library/Substrate/**"
    }

    includedirs { -- 头文件目录（实际是包含目录）
        "../Library/Substrate",
    } 

project "And64InlineHook" -- 项目名称
    architecture "ARM64"

    files { -- 项目文件
    "../Library/And64InlineHook/**"
    }

    includedirs { -- 头文件目录（实际是包含目录）
        "../Library/And64InlineHook",
    }

project "xDL" -- 项目名称
        files { -- 项目文件
        "../Library/xdl/**"
    }
    
    includedirs { -- 头文件目录（实际是包含目录）
        "../Library/xdl",
        "../Library/xdl/include",
    } 

    filter "platforms:ARM" -- arm模式的配置
        architecture "ARM"
    
    filter "platforms:ARM64" -- arm64模式的配置
        targetname "xDL64"
        architecture "ARM64"
        