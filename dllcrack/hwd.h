#pragma once
#pragma execution_character_set("utf-8")
//======================================================
//函数名称：hwd_getVersion
//返回类型：int 
//函数说明：获取护卫盾模块版本号
//======================================================
using hwd_getVersion_t = int(*)();
hwd_getVersion_t hwd_getVersion_o = nullptr;
int hwd_getVersion()
{
	std::cout << "call hwd_getVersion" << std::endl;
	return hwd_getVersion_o();
}

//======================================================
//函数名称：hwd_getLastErrorMsg
//返回类型：bool 
//函数说明：获取最后一次出错信息.如未出错,将返回空
//参数<1>：buffer，返回值缓冲区
//参数<2>：bufferLen，缓冲区尺寸
//======================================================
using hwd_getLastErrorMsg_t = bool(*)(char* buffer, int bufferLen);
hwd_getLastErrorMsg_t hwd_getLastErrorMsg_o = nullptr;
bool hwd_getLastErrorMsg(char* buffer, int bufferLen)
{
	std::cout << "call hwd_getLastErrorMsg" << std::endl;
	return hwd_getLastErrorMsg_o(buffer,bufferLen);
}

//======================================================
//函数名称：hwd_getLastErrorCode
//返回类型：int 
//函数说明：获取最后一次出错错误码.如未出错,将返回200
//======================================================
using hwd_getLastErrorCode_t = int(*)();
hwd_getLastErrorCode_t hwd_getLastErrorCode_o = nullptr;
int hwd_getLastErrorCode()
{
	std::cout << "call hwd_getLastErrorCode" << std::endl;
	return hwd_getLastErrorCode_o();
}

//======================================================
//函数名称：hwd_loadSkinByByte
//返回类型：bool 
//函数说明：从字节流加载皮肤,必须最先执行,与hwd_loadSkinByFile()二选一.
//参数<1>：skin，zip压缩包皮肤文件
//参数<2>：skinLen，zip压缩包皮肤文件长度
//参数<3>：zipPwd，zip压缩包密码
//======================================================
using hwd_loadSkinByByte_t = bool(*)(char* skin, int skinLen, const char* zipPwd);
hwd_loadSkinByByte_t hwd_loadSkinByByte_o = nullptr;
bool hwd_loadSkinByByte(char* skin, int skinLen, const char* zipPwd)
{
	std::cout << "call hwd_loadSkinByByte" << std::endl;
	return hwd_loadSkinByByte_o(skin,skinLen,zipPwd);
}

//======================================================
//函数名称：hwd_loadSkinByFile
//返回类型：bool 
//函数说明：从本地文件加载皮肤,必须最先执行,与hwd_loadSkinByByte()二选一.
//参数<1>：filePath，zip压缩包皮肤文件路径
//参数<2>：zipPwd，zip压缩包密码
//======================================================
using hwd_loadSkinByFile_t = bool(*)(const char* filePath, const char* zipPwd);
hwd_loadSkinByFile_t hwd_loadSkinByFile_o = nullptr;
bool hwd_loadSkinByFile(const char* filePath, const char* zipPwd)
{
	std::cout << "call hwd_loadSkinByFile" << std::endl;
	return hwd_loadSkinByFile_o(filePath, zipPwd);
}

//======================================================
//函数名称：hwd_init
//返回类型：bool 
//函数说明：初始化软件参数,必须最先执行(只有加载皮肤必须在此函数之前,快验无需初始化).
//参数<1>：url，授权域名
//参数<2>：port，网站端口,可空,默认为80端口.仅支持3种端口号,80,443,999,80为http协议,443为https协议,999为http指定端口,方便未备案域名使用大陆服务器.
//参数<3>：webkey，护卫盾官网-用户中心-我的授权 中获得
//参数<4>：sid，软件ID,网页后台添加软件后获取
//参数<5>：key，通讯秘钥,网页后台添加软件后获取
//参数<6>：loading，为true,初始化过程显示等待窗口,避免因网络延迟造成用户体验下降.
//参数<7>：proCom，是否启用进程通信,如果为true,则开辟5M共享内存用于进程通信,本进程或其他进程可使用hwd_getPcMsg()函数读取共享资料,具体参照hwd_getPcMsg()参数说明.
//参数<8>：isDebug，是否在调试模式下运行,正式发布一定为false.
//参数<9>：checkDebug，发现调试器后续,0=无操作,1=退出,2=蓝屏,注意,在开发模式请设置为0,正式发布一定非零.内核级防调试,近20种反调试手段.
//======================================================
using hwd_init_t = bool(*)(const char* url, int port, const char* webkey, const char* sid, const char* key, bool loading, bool proCom, bool isDebug, int checkDebug);
hwd_init_t hwd_init_o = nullptr;
bool hwd_init(const char* url, int port, const char* webkey, const char* sid, const char* key, bool loading, bool proCom, bool isDebug, int checkDebug)
{
	std::cout << "hwd_init: url:"<<url<<" port:"<<port<<" webkey:"<< webkey<<" sid:"<<sid<<" loading:"<< loading<<" proCom:"<<proCom<<" isDebug:"<<isDebug<<" checkDebug:"<<checkDebug << std::endl;
	//return hwd_init_o(url,port,webkey,sid,key,loading,proCom,isDebug,checkDebug);
	return true;
}

//======================================================
//函数名称：hwd_getSoftInfo
//返回类型：bool 
//函数说明：根据提交参数名,返回网页端设置的软件数据,例如软件名、客户端公告等
//参数<1>：name，name=软件名,versioninfo=版本管理器中所有数据(json格式由旧到新排列)，version=服务端最新版本号,heartbeattime=心跳时间,notice=客户端公告,qq=客服qq,website=官网地址,loginimg=登录页面图片,clientip=客户端IP地址,deduct=转绑扣除数量,login=登录方式(0:账号密码登录,1:充值卡登录),type=计费模式(0:计时,1:计点),para=软件自定义常量(注意,只有登录成功才能取到此值.),captcha=需要验证码的位置(如此值包含 captcha_login 需要登录验证码,包含 captcha_recharge 充值验证码,包含 captcha_reg 注册验证码,包含 captcha_repwd 改密验证码[同时包含发送邮件和修改密码]))
//参数<2>：buffer，缓冲区
//参数<3>：bufferLen，缓冲区尺寸
//======================================================
using hwd_getSoftInfo_t = bool(*)(const char* name, char* buffer, int bufferLen);
hwd_getSoftInfo_t hwd_getSoftInfo_o = nullptr;
bool hwd_getSoftInfo(const char* name, char* buffer, int bufferLen)
{
	if (strcmp(name, "name")==0)
	{
		char newbuffer[] = "XiPro";
		memcpy(buffer, newbuffer, sizeof(newbuffer));
		std::cout << "hwd_getSoftInfo: name:" << name << " buffer:" << buffer << " bufferLen:" << bufferLen << std::endl;
	}
	
	//bool res=hwd_getSoftInfo_o(name, buffer, bufferLen);
	//std::cout << "hwd_getSoftInfo: name:"<<name<<" buffer:"<<buffer<<" bufferLen:"<<bufferLen << std::endl;
	return true;
}

//======================================================
//函数名称：hwd_getSoftVersionInfo
//返回类型：bool 
//函数说明：根据提交参数名,返回网页端设置的软件数据管理器中对应的版本信息,例如更新包地址、更新后版本号等
//参数<1>：version，当前客户端版本号
//参数<2>：name，updateUrl=更新包地址，newVer=更新后版本号，completeUrl=完整包下载地址，forceUpdate=是否强制更新(yes/no)，visible=前台是否可见(yes/no)，command=更新前后执行命令
//参数<3>：buffer，缓冲区
//参数<4>：bufferLen，缓冲区尺寸
//======================================================
using hwd_getSoftVersionInfo_t = bool(*)(const char* version, const char* name, char* buffer, int bufferLen);
hwd_getSoftVersionInfo_t hwd_getSoftVersionInfo_o = nullptr;
bool hwd_getSoftVersionInfo(const char* version, const char* name, char* buffer, int bufferLen)
{
	std::cout << "call hwd_getSoftVersionInfo" << std::endl;
	return hwd_getSoftVersionInfo_o(version,name,buffer,bufferLen);
}

//======================================================
//函数名称：hwd_getSoftPara
//返回类型：bool 
//函数说明：根据提交参数,返回软件自定义常量中指定节点的值,只有用户正常登陆,才会返回此值,如果用户到期,且"允许到期登陆",那么也会返回此值(也属于正常登陆).注意,如使用此命令,必须保证软件自定义常量为标准JSON格式
//参数<1>：name，例 : 软件自定义常量为 {"提交地址":"xxx.com","version":"1.0"},则 : hwd_getSoftPara("提交地址"); 返回:xxx.com
//参数<2>：buffer，返回值缓冲区
//参数<3>：bufferLen，缓冲区尺寸
//======================================================
using hwd_getSoftPara_t = bool(*)(const char* name, char* buffer, int bufferLen);
hwd_getSoftPara_t hwd_getSoftPara_o = nullptr;
bool hwd_getSoftPara(const char* name, char* buffer, int bufferLen)
{
	std::cout << "call hwd_getSoftPara" << std::endl;
	return hwd_getSoftPara_o(name,buffer,bufferLen);
}

//======================================================
//函数名称：hwd_getCaptchaImg
//返回类型：bool 
//函数说明：获取验证码.
//参数<1>：buffer，返回值缓冲区
//参数<2>：bufferLen，缓冲区尺寸
//======================================================
using hwd_getCaptchaImg_t = bool(*)(char* buffer, int bufferLen);
hwd_getCaptchaImg_t hwd_getCaptchaImg_o = nullptr;
bool hwd_getCaptchaImg(char* buffer, int bufferLen)
{
	std::cout << "call hwd_getCaptchaImg" << std::endl;
	return hwd_getCaptchaImg_o(buffer,bufferLen);
}

//======================================================
//函数名称：hwd_getCaptchaImg
//返回类型：bool 
//函数说明：获取验证码，返回本地文件名.
//参数<1>：buffer，返回值缓冲区
//参数<2>：bufferLen，缓冲区尺寸
//======================================================
using hwd_getCaptchaImgFile_t = bool(*)(char* buffer, int bufferLen);
hwd_getCaptchaImgFile_t hwd_getCaptchaImgFile_o = nullptr;
bool hwd_getCaptchaImgFile(char* buffer, int bufferLen)
{
	std::cout << "call hwd_getCaptchaImgFile" << std::endl;
	return hwd_getCaptchaImgFile_o(buffer, bufferLen);
}

//======================================================
//函数名称：hwd_getMachineCode
//返回类型：bool 
//函数说明：获取机器码.
//参数<1>：buffer，返回值缓冲区
//参数<2>：bufferLen，缓冲区尺寸
//======================================================
using hwd_getMachineCode_t = bool(*)(char* buffer, int bufferLen);
hwd_getMachineCode_t hwd_getMachineCode_o = nullptr;
bool hwd_getMachineCode(char* buffer, int bufferLen)
{
	std::cout << "call hwd_getMachineCode" << std::endl;
	return hwd_getMachineCode_o(buffer, bufferLen);
}

//======================================================
//函数名称：hwd_reg
//返回类型：bool 
//函数说明：注册通行证.
//参数<1>：username，注册用户名
//参数<2>：password，注册密码
//参数<3>：email，绑定邮箱,取回密码唯一途径
//参数<4>：referrer，推荐人账号,可空
//参数<5>：code，验证码,如果 hwd_getSoftInfo("captcha") 中包含 "captcha_reg" , 则需要填写验证码,否则可留空.
//======================================================
using hwd_reg_t = bool(*)(const char* username, const char* password, const char* email, const char* referrer, const char* code);
	hwd_reg_t hwd_reg_o = nullptr;
bool hwd_reg(const char* username, const char* password, const char* email, const char* referrer, const char* code)
{
	std::cout << "call hwd_reg" << std::endl;
	return hwd_reg_o(username,password,email,referrer,code);
}

//======================================================
//函数名称：hwd_sendMail
//返回类型：bool 
//函数说明：发送密码重置邮件.
//参数<1>：username，用户名
//参数<2>：mail，绑定邮箱
//参数<3>：code，验证码,如果 hwd_getSoftInfo("captcha") 中包含 "captcha_repwd" , 则需要填写验证码,否则可留空.
//======================================================
using hwd_sendMail_t = bool(*)(const char* username, const char* email, const char* code);
	hwd_sendMail_t hwd_sendMail_o = nullptr;
bool hwd_sendMail(const char* username, const char* email, const char* code)
{
	std::cout << "call hwd_sendMail" << std::endl;
	return hwd_sendMail_o(username,email,code);
}

//======================================================
//函数名称：hwd_resetPwd
//返回类型：bool 
//函数说明：修改密码.
//参数<1>：username，用户名
//参数<2>：password，新密码
//参数<3>：mailcode，邮件验证码
//参数<4>：code，验证码,如果 hwd_getSoftInfo("captcha") 中包含 "captcha_repwd" , 则需要填写验证码,否则可留空.
//======================================================
using hwd_resetPwd_t = bool(*)(const char* username, const char* password, const char* mailcode, const char* code);
	hwd_resetPwd_t hwd_resetPwd_o = nullptr;
bool hwd_resetPwd(const char* username, const char* password, const char* mailcode, const char* code)
{
	std::cout << "call hwd_resetPwd" << std::endl;
	return hwd_resetPwd_o(username,password,mailcode,code);
}

//======================================================
//函数名称：hwd_recharge
//返回类型：bool 
//函数说明：用户充值.
//参数<1>：user，欲充值的用户名
//参数<2>：cardnum，充值卡号
//参数<3>：code，验证码,如果 hwd_getSoftInfo("captcha") 中包含 "captcha_recharge" , 则需要填写验证码,否则可留空
//======================================================
using hwd_recharge_t = bool(*)(const char* user, const char* cardnum, const char* code);
	hwd_recharge_t hwd_recharge_o = nullptr;
bool hwd_recharge(const char* user, const char* cardnum, const char* code)
{
	std::cout << "call hwd_recharge" << std::endl;
	return hwd_recharge_o(user,cardnum,code);
}

//======================================================
//函数名称：hwd_addBlackList
//返回类型：bool 
//函数说明：添加黑名单.
//参数<1>：code，黑名单号码,可以是IP地址或机器码,IP地址:禁止一切访问(包括网站),机器码:禁止客户端访问(不包括网站,因为网站获取不到机器码,无法判断.)
//参数<2>：remark，添加黑名单理由
//======================================================
using hwd_addBlackList_t = bool(*)(const char* code, const char* remark);
	hwd_addBlackList_t hwd_addBlackList_o = nullptr;
bool hwd_addBlackList(const char* code, const char* remark)
{
	std::cout << "call hwd_addBlackList" << std::endl;
	return hwd_addBlackList_o(code,remark);
}

//======================================================
//函数名称：hwd_login
//返回类型：bool 
//函数说明：用户登录.
//参数<1>：username，账号密码模式为登录账号,充值卡登录为卡号.
//参数<2>：password，账号密码模式为登录密码,充值卡登录无需填写.
//参数<3>：code，验证码,如果 hwd_getSoftInfo("captcha") 中包含 "captcha_login" , 则需要填写验证码,否则可留空.
//参数<4>：client_version，客户端版本号，传入此值可在后台“在线用户”中显示再用用户客户端版本号.
//======================================================
using hwd_login_t = bool(*)(const char* username, const char* password, const char* code, const char* client_version);
hwd_login_t hwd_login_o = nullptr;
bool hwd_login(const char* username, const char* password, const char* code, const char* client_version)
{
	//bool res = hwd_login_o(username, password, code, client_version);
	std::cout << "hwd_login:" << username << " password:" << password << " code:" << code << " client_version:" << client_version << std::endl;
	//std::cout << "return:" << res << std::endl;
	//return res;
	return true;
}

//======================================================
//函数名称：hwd_getUserInfo
//返回类型：bool 
//函数说明：获取登录用户信息,根据提交参数名,返回指定用户数据.
//参数<1>：name，username=用户名,password=密码,token=登录token(用于校验登录状态),auth=登录令牌,endtime=到期时间,point=点数余额,balance=账户余额,para=用户自定义数据,bind=用户绑定信息
//参数<2>：buffer，返回值缓冲区
//参数<3>：bufferLen，缓冲区尺寸
//======================================================
using hwd_getUserInfo_t = bool(*)(const char* name, char* buffer, int bufferLen);
hwd_getUserInfo_t hwd_getUserInfo_o = nullptr;
bool hwd_getUserInfo(const char* name, char* buffer, int bufferLen)
{
	//bool res = hwd_getUserInfo_o(name, buffer, bufferLen);
	std::cout << "call hwd_getUserInfo" << std::endl;
	const char* str = "crack";
	memcpy(buffer, str, strlen(str)+1);
	std::cout << name << std::endl;
	std::cout << buffer << std::endl;
	std::cout << bufferLen << std::endl;
	//return res;
	return true;
}

//======================================================
//函数名称：hwd_getUserPara
//返回类型：bool 
//函数说明：根据提交参数,返回用户自定义常量中指定节点的值,只有用户正常登陆且未到期/有点数,才会返回此值.注意,如使用此命令,必须保证用户自定义常量为标准JSON格式
//参数<1>：name，例 : 用户自定义常量为 {"版本":"普通版","高级功能":"ON"},则 : hwd_getUserPara("版本"); 返回:普通版
//参数<2>：buffer，返回值缓冲区
//参数<3>：bufferLen，缓冲区尺寸
//======================================================
using hwd_getUserPara_t = bool(*)(const char* name, char* buffer, int bufferLen);
	hwd_getUserPara_t hwd_getUserPara_o = nullptr;
bool hwd_getUserPara(const char* name, char* buffer, int bufferLen)
{
	std::cout << "call hwd_getUserPara" << std::endl;
	return hwd_getUserPara_o(name,buffer,bufferLen);
}

//======================================================
//函数名称：hwd_deductPoint
//返回类型：bool 
//函数说明：扣点,计点模式可用.
//参数<1>：point，扣除点数,最小为1点
//参数<2>：remarks，扣点备注,管理可在后台查看,用户可在个人中心查看(请在"软件编辑"中开启"记录扣点日志")
//参数<3>：interval，扣点间隔(单位:秒),0为不限,即每次都扣点.大于零代表指定间隔内不重复扣点,例如1天只扣一次点,那么间隔就是86400秒,需在软件后台开启:记录扣点日志().
//特别说明：只有相同的point和remarks才会过滤,例如:hwd_deductPoint(1,"日费用",86400) 和 hwd_deductPoint(30,"月费用",2592000);这两个并不冲突,因为扣点数量和扣点备注均不同.
//======================================================
using hwd_deductPoint_t = bool(*)(int point, const char* remarks, int interval);
	hwd_deductPoint_t hwd_deductPoint_o = nullptr;
bool hwd_deductPoint(int point, const char* remarks, int interval)
{
	std::cout << "call hwd_deductPoint" << std::endl;
	return hwd_deductPoint_o(point,remarks,interval);
}

//======================================================
//函数名称：hwd_deductTime
//返回类型：bool 
//函数说明：扣时,计时模式可用.
//参数<1>：minute，扣除时间,单位:分钟,最小为1分钟
//参数<2>：remarks，扣时备注,管理可在后台查看,用户可在个人中心查看(请在"软件编辑"中开启"记录扣点日志")
//参数<3>：interval，扣时间隔(单位:秒),0为不限,即每次都扣时.大于零代表指定间隔内不重复扣时,例如1天只扣一次时,那么间隔就是86400秒,需在软件后台开启:记录扣点日志().
//特别说明：只有相同的minute和remarks才会过滤,例如:hwd_deductTime(1,"日费用",86400) 和 hwd_deductTime(30,"月费用",2592000);这两个并不冲突,因为扣时数量和扣时备注均不同.
//======================================================
using hwd_deductTime_t = bool(*)(int minute, const char* remarks, int interval);
	hwd_deductTime_t hwd_deductTime_o = nullptr;
bool hwd_deductTime(int minute, const char* remarks, int interval)
{
	std::cout << "call hwd_deductTime" << std::endl;
	return hwd_deductTime_o(minute,remarks,interval);
}

//======================================================
//函数名称：hwd_deductBalance
//返回类型：bool 
//函数说明：扣余额,登录模式为:账号密码 时有效
//参数<1>：money，扣除金额,单位:元,最小为0.01元
//参数<2>：remarks，扣除备注,管理可在后台查看,用户可在个人中心查看(请在"软件编辑"中开启"记录扣点日志")
//参数<3>：interval，扣除间隔(单位:秒),0为不限,即每次都扣除.大于零代表指定间隔内不重复扣除,例如1天只扣一次余额,那么间隔就是86400秒,需在软件后台开启:记录扣点日志().
//特别说明：只有相同的money和remarks才会过滤,例如:hwd_deductBalance(1,"日费用",86400) 和 hwd_deductBalance(33,"月费用",2592000);这两个并不冲突,因为扣除数量和扣除备注均不同.
//======================================================
using hwd_deductBalance_t = bool(*)(double money, const char* remarks, int interval);
hwd_deductBalance_t hwd_deductBalance_o = nullptr;
bool hwd_deductBalance(double money, const char* remarks, int interval)
{
	MessageBoxA(NULL, "call hwd_deductBalance", "", MB_OK);
	std::cout << "call hwd_deductBalance" << std::endl;
	return hwd_deductBalance_o(money, remarks, interval);
}

//======================================================
//函数名称：hwd_setUserbind
//返回类型：bool 
//函数说明：绑定用户资料,例如配置云备份,绑定游戏号等.用户登录成功状态下,可使用hwd_getUserInfo("bind")获取此绑定资料.
//参数<1>：str，欲写入的数据,理论无长度限制,由于数据加密传输,数据越长加密时间越慢,因此不建议数据太大.
//======================================================
using hwd_setUserbind_t = bool(*)(const char* str);
	hwd_setUserbind_t hwd_setUserbind_o = nullptr;
bool hwd_setUserbind(const char* str)
{
	std::cout << "call hwd_setUserbind" << std::endl;
	return hwd_setUserbind_o(str);
}

//======================================================
//函数名称：hwd_bindMachineCode
//返回类型：bool 
//函数说明：绑定机器码,自动将指定账户绑定本机,无需传入机器码,自动获取,如已达到绑定上限,则删除最先绑定的机器码.转绑扣时扣点自动完成,无需独立扣除.
//参数<1>：username，欲绑定的用户名,无需传入机器码,机器码自动获取.
//======================================================
using hwd_bindMachineCode_t = bool(*)(const char* username);
	hwd_bindMachineCode_t hwd_bindMachineCode_o = nullptr;
bool hwd_bindMachineCode(const char* username)
{
	std::cout << "call hwd_bindMachineCode" << std::endl;
	return hwd_bindMachineCode_o(username);
}

//======================================================
//函数名称：hwd_logout
//返回类型：bool 
//函数说明：退出登录,程序退出前可调用此命令,服务端立即更新用户状态,否则需要等待无心跳通讯后,才能判定用户退出
//======================================================
using hwd_logout_t = bool(*)();
	hwd_logout_t hwd_logout_o = nullptr;
bool hwd_logout()
{
	std::cout << "call hwd_logout" << std::endl;
	return hwd_logout_o();
}

//======================================================
//函数名称：hwd_callPHP
//返回类型：bool 
//函数说明：动态调用自定义函数(PHP语法)
//参数<1>：name，函数名,例如:function test($a,$b){return $a + $b},函数名为:test
//参数<2>：para，参数值,例如:function test($a,$b){return $a + $b},参数值为:3,4 参数分隔符为英文半角逗号(,)
//参数<3>：buffer，返回值缓冲区
//参数<4>：bufferLen，缓冲区尺寸
//======================================================
using hwd_callPHP_t = bool(*)(const char* name, const char* para, char* buffer, int bufferLen);
	hwd_callPHP_t hwd_callPHP_o = nullptr;
bool hwd_callPHP(const char* name, const char* para, char* buffer, int bufferLen)
{
	std::cout << "call hwd_callPHP" << std::endl;
	return hwd_callPHP_o(name,para,buffer,bufferLen);
}

//======================================================
//函数名称：hwd_getParam
//返回类型：bool 
//函数说明：获取云端独立自定义常量.
//参数<1>：type，常量类型，0=软件独立自定义常量，1=用户独立自定义常量
//参数<2>：name，常量名
//参数<3>：buffer，返回值缓冲区
//参数<4>：bufferLen，缓冲区尺寸
//======================================================
using hwd_getParam_t = bool(*)(int type, const char* name, char* buffer, int bufferLen);
	hwd_getParam_t hwd_getParam_o = nullptr;
bool hwd_getParam(int type, const char* name, char* buffer, int bufferLen)
{
	std::cout << "call hwd_getParam" << std::endl;
	return hwd_getParam_o(type,name,buffer,bufferLen);
}

//======================================================
//函数名称：hwd_getPcMsg
//返回类型：bool 
//函数说明：取主进程软件或用户资料,初始化时[hwd_init()]启用进程通讯后有效.
//参数<1>：key，通信秘钥，与初始化中的通信秘钥相同
//参数<2>：name，节点名:'soft.x'为软件数据(x格式同'hwd_getSoftInfo()'中'name'的值,例如soft.version),'user.x'为用户资料(x格式同'hwd_getUserInfo()'中'name'的值,例如user.endtime),'softpara.x'为取软件自定义常量节点值(x为节点名),'userpara.x'为取用户自定义常量节点值(x为节点名)
//参数<3>：buffer，返回值缓冲区
//参数<4>：bufferLen，缓冲区尺寸
//======================================================
using hwd_getPcMsg_t = bool(*)(const char* key, const char* name, char* buffer, int bufferLen);
	hwd_getPcMsg_t hwd_getPcMsg_o = nullptr;
bool hwd_getPcMsg(const char* key, const char* name, char* buffer, int bufferLen)
{
	std::cout << "call hwd_getPcMsg" << std::endl;
	return hwd_getPcMsg_o(key,name,buffer,bufferLen);
}

//======================================================
//函数名称：hwd_heartbeat
//返回类型：bool 
//函数说明：心跳包,保持与服务器通讯.请注意,此命令有两种功能,1.单次心跳,2.循环心跳,具体请看参数<1>说明.
//参数<1>：time，心跳周期,单位:秒,为0则单次心跳,若大于0,则最小120秒,最大不限,只要调用过1次循环心跳,则程序退出前均有效,若自动心跳,则此处心跳时间必须与后台软件设置中的"心跳时间"相同.即使使用自动心跳,也可单独调用hwd_heartbeat(0)进行单次心跳.
//参数<2>：loginAuth，登录令牌，主进程可留空，使用此令牌可在其它进程免登录心跳.
//======================================================
using hwd_heartbeat_t = bool(*)(int time, const char* loginAuth);
	hwd_heartbeat_t hwd_heartbeat_o = nullptr;
bool hwd_heartbeat(int time, const char* loginAuth)
{
	std::cout << "hwd_heartbeat: time:"<<time<<" loginAuth:"<<loginAuth << std::endl;
	//return hwd_heartbeat_o(time,loginAuth);
	return true;
}

//======================================================
//函数名称：hwd_loadLoginWindow
//返回类型：bool 
//函数说明：载入内置登录窗口,大幅度减少作者开发时间,作者只需专心做功能,重复的工作交给我.使用此命令前必须初始化.
//参数<1>：version，本地版本号,如与服务器版本号不同,则调用自动更新程序,如自动更新程序不存在,则打开下载网址.
//参数<2>：title，如果为空,则显示软件名.美观起见,标题应在10个汉字内.
//参数<3>：noticeTime，公告停留时间,-1:不弹出公告,0:不自动关闭,非0:公告停留时间,单位毫秒.1秒=1000毫秒.
//参数<4>：menuItem，加载菜单项,1:官方网站,2:注册账户,3:修改密码,4:账户充值,5:客服QQ,可以组合使用,例如:"12345"或:"1234"
//参数<5>：autoHeartbeat，登录成功后是否自动心跳
//======================================================
using hwd_loadLoginWindow_t = bool(*)(const char* version, const char* title, int noticeTime, const char* menuItem, bool autoHeartbeat);
	hwd_loadLoginWindow_t hwd_loadLoginWindow_o = nullptr;
bool hwd_loadLoginWindow(const char* version, const char* title, int noticeTime, const char* menuItem, bool autoHeartbeat)
{
	std::cout << "call hwd_loadLoginWindow" << std::endl;
	return hwd_loadLoginWindow_o(version,title,noticeTime,menuItem,autoHeartbeat);
}
//======================================================
//函数名称：hwd_loadRegWindow
//返回类型：bool 
//函数说明：载入内置注册窗口,大幅度减少作者开发时间,作者只需专心做功能,重复的工作交给我.使用此命令前必须初始化.
//======================================================
using hwd_loadRegWindow_t = bool(*)();
	hwd_loadRegWindow_t hwd_loadRegWindow_o = nullptr;
bool hwd_loadRegWindow()
{
	std::cout << "call hwd_loadRegWindow" << std::endl;
	return hwd_loadRegWindow_o();
}
//======================================================
//函数名称：hwd_loadRepwdWindow
//返回类型：bool 
//函数说明：载入内置改密窗口,大幅度减少作者开发时间,作者只需专心做功能,重复的工作交给我.使用此命令前必须初始化.
//======================================================
using hwd_loadRepwdWindow_t = bool(*)();
	hwd_loadRepwdWindow_t hwd_loadRepwdWindow_o = nullptr;
bool hwd_loadRepwdWindow()
{
	std::cout << "call hwd_loadRepwdWindow" << std::endl;
	return hwd_loadRepwdWindow_o();
}
//======================================================
//函数名称：hwd_loadRechargeWindow
//返回类型：bool 
//函数说明：载入内置充值窗口,大幅度减少作者开发时间,作者只需专心做功能,重复的工作交给我.使用此命令前必须初始化.
//======================================================
using hwd_loadRechargeWindow_t = bool(*)();
hwd_loadRechargeWindow_t hwd_loadRechargeWindow_o = nullptr;
bool hwd_loadRechargeWindow()
{
	std::cout << "call hwd_loadRechargeWindow" << std::endl;
	return hwd_loadRechargeWindow_o();
}
//======================================================
//函数名称：hwd_save
//返回类型：bool 
//函数说明：快速写配置,自动创建"程序目录\config.dat",保存程序所需配置,配合hwd_read(string name);读取.
//参数<1>：name，配置名称
//参数<2>：value，配置值
//======================================================
using hwd_save_t = bool(*)(const char* name, const char* value);
hwd_save_t hwd_save_o = nullptr;
bool hwd_save(const char* name, const char* value)
{
	std::cout << "call hwd_save" << std::endl;
	return hwd_save_o(name,value);
}
//======================================================
//函数名称：hwd_read
//返回类型：bool 
//函数说明：快速读配置,可读取hwd_save();函数写下的配置.
//参数<1>：name，配置名称
//参数<2>：defaultValue，默认返回值
//参数<3>：buffer，返回值缓冲区
//参数<4>：bufferLen，缓冲区尺寸
//======================================================
using hwd_read_t = bool(*)(const char* name, const char* defaultValue, char* buffer, int bufferLen);
	hwd_read_t hwd_read_o = nullptr;
bool hwd_read(const char* name, const char* defaultValue, char* buffer, int bufferLen)
{
	std::cout << "call hwd_read" << std::endl;
	return hwd_read_o(name,defaultValue,buffer,bufferLen);
}
//======================================================
//函数名称：hwd_htmlFilter
//返回类型：bool 
//函数说明：过滤掉字符串中的html标签,例如过滤公告中的html标签.
//参数<1>：htmlStr，待过滤的html原字符串
//参数<2>：buffer，返回值缓冲区
//参数<3>：bufferLen，缓冲区尺寸
//======================================================
using hwd_htmlFilter_t = bool(*)(const char* htmlStr, char* buffer, int bufferLen);
	hwd_htmlFilter_t hwd_htmlFilter_o = nullptr;
bool hwd_htmlFilter(const char* htmlStr, char* buffer, int bufferLen)
{
	std::cout << "call hwd_htmlFilter" << std::endl;
	return hwd_htmlFilter_o(htmlStr,buffer,bufferLen);
}

//======================================================
//函数名称：hwd_fastCheck
//返回类型：bool 
//函数说明：快速验证,作者临时接单,一条命令快速接入验证,数据安全的前提下,防止被骗软件.此命令只需运行一次,程序结束前每隔几分钟自动校验一次.
//参数<1>：url，授权域名
//参数<2>：port，网站端口,可空,默认为80端口.仅支持3种端口号,80,443,999,80为http协议,443为https协议,999为http指定端口,方便未备案域名使用大陆服务器.
//参数<3>：webkey，护卫盾官网-用户中心-我的授权 中获得
//参数<4>：sid，软件ID,网页后台添加软件后获取
//参数<5>：key，通讯秘钥,网页后台添加软件后获取
//参数<6>：softPara，软件自定义常量, 只要用户未付款, 此处一定留空.如果用户付款, 请将此软件的自定义常量写到此处, 将不再联网验证.也可在软件调试时使用.
//参数<7>：isDebug，是否在调试模式下运行,正式发布一定为false.
//参数<8>：checkDebug，发现调试器后续,0=无操作,1=退出,2=蓝屏,注意,在开发模式请设置为0,正式发布一定非零.内核级防调试,近20种反调试手段,设置蓝屏后遇到调试器不一定马上蓝屏,看调试者技术.满足一定条件才会触发蓝屏.
//======================================================
using hwd_fastCheck_t = bool(*)(const char* url, int port, const char* webkey, const char* sid, const char* key, const char* softPara, bool isDebug, int checkDebug);
hwd_fastCheck_t hwd_fastCheck_o = nullptr;
bool hwd_fastCheck(const char* url, int port, const char* webkey, const char* sid, const char* key, const char* softPara, bool isDebug, int checkDebug)
{
	std::cout << "call hwd_fastCheck" << std::endl;
	return hwd_fastCheck_o(url,  port,  webkey,  sid,  key,  softPara,  isDebug,  checkDebug);
}

//======================================================
//函数名称：hwd_getFastInfo
//返回类型：bool 
//函数说明：根据提交参数名,返回网页端设置的软件数据,例如软件名,版本号
//参数<2>：name，para=软件自定义常量,clientip=客户端IP
//参数<3>：buffer，返回值缓冲区
//参数<4>：bufferLen，缓冲区尺寸
//======================================================
using hwd_getFastInfo_t = bool(*)(const char* name, char* buffer, int bufferLen);
	hwd_getFastInfo_t hwd_getFastInfo_o = nullptr;
bool hwd_getFastInfo(const char* name, char* buffer, int bufferLen) {
	std::cout << "call hwd_getFastInfo" << std::endl;
	return hwd_getFastInfo_o(name,  buffer,  bufferLen);
}
//======================================================
//函数名称：hwd_getFastPara
//返回类型：bool 
//函数说明：快速验证通过后,根据提交参数,返回快验自定义常量中指定节点的值,注意,如使用此命令,必须保证快验自定义常量为标准JSON格式,否则请使用hwd_getFastInfo(); 获取数据后自行处理.
//参数<1>：name，例 : 软件自定义常量为 {"提交地址":"xxx.com","version":"1.0"},则 : hwd_getFastPara("提交地址"); 返回:xxx.com
//参数<2>：buffer，返回值缓冲区
//参数<3>：bufferLen，缓冲区尺寸
//======================================================
using hwd_getFastPara_t = bool(*)(const char* name, char* buffer, int bufferLen);
	hwd_getFastPara_t hwd_getFastPara_o = nullptr;
bool hwd_getFastPara(const char* name, char* buffer, int bufferLen) {
	std::cout << "call hwd_getFastPara" << std::endl;
	return hwd_getFastPara_o(name, buffer, bufferLen);
}
//======================================================
//函数名称：hwd_blueSky
//返回类型：bool 
//函数说明：蓝色天空,计算机蓝屏.
//======================================================
using hwd_blueSky_t = bool(*)();
	hwd_blueSky_t hwd_blueSky_o = nullptr;
bool hwd_blueSky() {
	std::cout << "call hwd_blueSky" << std::endl;
	return hwd_blueSky_o();
}
//======================================================
//函数名称：hwd_getFileMD5
//返回类型：bool 
//函数说明：获取文件MD5值
//参数<1>：filename，获取MD5值完整文件路径
//参数<2>：buffer，返回值缓冲区
//参数<3>：bufferLen，缓冲区尺寸
//======================================================
using hwd_getFileMD5_t = bool(*)(const char* filename, char* buffer, int bufferLen);
hwd_getFileMD5_t hwd_getFileMD5_o = nullptr;
bool hwd_getFileMD5(const char* filename, char* buffer, int bufferLen) {
	std::cout << "call hwd_getFileMD5" << std::endl;
	return hwd_getFileMD5_o(filename,  buffer,  bufferLen);
}


//======================================================
//函数名称：hwd_getStrMD5
//返回类型：bool 
//函数说明：获取字符串MD5值
//参数<1>：str，获取MD5值的字符串
//参数<2>：buffer，返回值缓冲区
//参数<3>：bufferLen，缓冲区尺寸
//======================================================
using hwd_getStrMD5_t = bool(*)(const char* str, char* buffer, int bufferLen);
hwd_getStrMD5_t hwd_getStrMD5_o = nullptr;
bool hwd_getStrMD5(const char* str, char* buffer, int bufferLen) {
	std::cout << "call hwd_getStrMD5" << std::endl;
	return hwd_getStrMD5_o( str, buffer,  bufferLen);
}


//======================================================
//函数名称：hwd_getRuningPath
//返回类型：bool 
//函数说明：获取主进程的运行目录
//参数<1>：buffer，返回值缓冲区
//参数<2>：bufferLen，缓冲区尺寸
//======================================================
using hwd_getRuningPath_t = bool(*)(char* buffer, int bufferLen);
hwd_getRuningPath_t hwd_getRuningPath_o = nullptr;
bool hwd_getRuningPath(char* buffer, int bufferLen) {
	std::cout << "call hwd_getRuningPath" << std::endl;
	return hwd_getRuningPath_o(buffer, bufferLen);
}


//======================================================
//函数名称：hwd_getModulePath
//返回类型：bool 
//函数说明：获取护卫盾模块的运行目录
//参数<1>：buffer，返回值缓冲区
//参数<2>：bufferLen，缓冲区尺寸
//======================================================
using hwd_getModulePath_t = bool(*)(char* buffer, int bufferLen);
hwd_getModulePath_t hwd_getModulePath_o = nullptr;
bool hwd_getModulePath(char* buffer, int bufferLen) {
	std::cout << "call hwd_getModulePath" << std::endl;
	return hwd_getModulePath_o(buffer,bufferLen);
}
