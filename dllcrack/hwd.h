#pragma once
#pragma execution_character_set("utf-8")
//======================================================
//�������ƣ�hwd_getVersion
//�������ͣ�int 
//����˵������ȡ������ģ��汾��
//======================================================
using hwd_getVersion_t = int(*)();
hwd_getVersion_t hwd_getVersion_o = nullptr;
int hwd_getVersion()
{
	std::cout << "call hwd_getVersion" << std::endl;
	return hwd_getVersion_o();
}

//======================================================
//�������ƣ�hwd_getLastErrorMsg
//�������ͣ�bool 
//����˵������ȡ���һ�γ�����Ϣ.��δ����,�����ؿ�
//����<1>��buffer������ֵ������
//����<2>��bufferLen���������ߴ�
//======================================================
using hwd_getLastErrorMsg_t = bool(*)(char* buffer, int bufferLen);
hwd_getLastErrorMsg_t hwd_getLastErrorMsg_o = nullptr;
bool hwd_getLastErrorMsg(char* buffer, int bufferLen)
{
	std::cout << "call hwd_getLastErrorMsg" << std::endl;
	return hwd_getLastErrorMsg_o(buffer,bufferLen);
}

//======================================================
//�������ƣ�hwd_getLastErrorCode
//�������ͣ�int 
//����˵������ȡ���һ�γ��������.��δ����,������200
//======================================================
using hwd_getLastErrorCode_t = int(*)();
hwd_getLastErrorCode_t hwd_getLastErrorCode_o = nullptr;
int hwd_getLastErrorCode()
{
	std::cout << "call hwd_getLastErrorCode" << std::endl;
	return hwd_getLastErrorCode_o();
}

//======================================================
//�������ƣ�hwd_loadSkinByByte
//�������ͣ�bool 
//����˵�������ֽ�������Ƥ��,��������ִ��,��hwd_loadSkinByFile()��ѡһ.
//����<1>��skin��zipѹ����Ƥ���ļ�
//����<2>��skinLen��zipѹ����Ƥ���ļ�����
//����<3>��zipPwd��zipѹ��������
//======================================================
using hwd_loadSkinByByte_t = bool(*)(char* skin, int skinLen, const char* zipPwd);
hwd_loadSkinByByte_t hwd_loadSkinByByte_o = nullptr;
bool hwd_loadSkinByByte(char* skin, int skinLen, const char* zipPwd)
{
	std::cout << "call hwd_loadSkinByByte" << std::endl;
	return hwd_loadSkinByByte_o(skin,skinLen,zipPwd);
}

//======================================================
//�������ƣ�hwd_loadSkinByFile
//�������ͣ�bool 
//����˵�����ӱ����ļ�����Ƥ��,��������ִ��,��hwd_loadSkinByByte()��ѡһ.
//����<1>��filePath��zipѹ����Ƥ���ļ�·��
//����<2>��zipPwd��zipѹ��������
//======================================================
using hwd_loadSkinByFile_t = bool(*)(const char* filePath, const char* zipPwd);
hwd_loadSkinByFile_t hwd_loadSkinByFile_o = nullptr;
bool hwd_loadSkinByFile(const char* filePath, const char* zipPwd)
{
	std::cout << "call hwd_loadSkinByFile" << std::endl;
	return hwd_loadSkinByFile_o(filePath, zipPwd);
}

//======================================================
//�������ƣ�hwd_init
//�������ͣ�bool 
//����˵������ʼ���������,��������ִ��(ֻ�м���Ƥ�������ڴ˺���֮ǰ,���������ʼ��).
//����<1>��url����Ȩ����
//����<2>��port����վ�˿�,�ɿ�,Ĭ��Ϊ80�˿�.��֧��3�ֶ˿ں�,80,443,999,80ΪhttpЭ��,443ΪhttpsЭ��,999Ϊhttpָ���˿�,����δ��������ʹ�ô�½������.
//����<3>��webkey�������ܹ���-�û�����-�ҵ���Ȩ �л��
//����<4>��sid�����ID,��ҳ��̨���������ȡ
//����<5>��key��ͨѶ��Կ,��ҳ��̨���������ȡ
//����<6>��loading��Ϊtrue,��ʼ��������ʾ�ȴ�����,�����������ӳ�����û������½�.
//����<7>��proCom���Ƿ����ý���ͨ��,���Ϊtrue,�򿪱�5M�����ڴ����ڽ���ͨ��,�����̻��������̿�ʹ��hwd_getPcMsg()������ȡ��������,�������hwd_getPcMsg()����˵��.
//����<8>��isDebug���Ƿ��ڵ���ģʽ������,��ʽ����һ��Ϊfalse.
//����<9>��checkDebug�����ֵ���������,0=�޲���,1=�˳�,2=����,ע��,�ڿ���ģʽ������Ϊ0,��ʽ����һ������.�ں˼�������,��20�ַ������ֶ�.
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
//�������ƣ�hwd_getSoftInfo
//�������ͣ�bool 
//����˵���������ύ������,������ҳ�����õ��������,������������ͻ��˹����
//����<1>��name��name=�����,versioninfo=�汾����������������(json��ʽ�ɾɵ�������)��version=��������°汾��,heartbeattime=����ʱ��,notice=�ͻ��˹���,qq=�ͷ�qq,website=������ַ,loginimg=��¼ҳ��ͼƬ,clientip=�ͻ���IP��ַ,deduct=ת��۳�����,login=��¼��ʽ(0:�˺������¼,1:��ֵ����¼),type=�Ʒ�ģʽ(0:��ʱ,1:�Ƶ�),para=����Զ��峣��(ע��,ֻ�е�¼�ɹ�����ȡ����ֵ.),captcha=��Ҫ��֤���λ��(���ֵ���� captcha_login ��Ҫ��¼��֤��,���� captcha_recharge ��ֵ��֤��,���� captcha_reg ע����֤��,���� captcha_repwd ������֤��[ͬʱ���������ʼ����޸�����]))
//����<2>��buffer��������
//����<3>��bufferLen���������ߴ�
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
//�������ƣ�hwd_getSoftVersionInfo
//�������ͣ�bool 
//����˵���������ύ������,������ҳ�����õ�������ݹ������ж�Ӧ�İ汾��Ϣ,������°���ַ�����º�汾�ŵ�
//����<1>��version����ǰ�ͻ��˰汾��
//����<2>��name��updateUrl=���°���ַ��newVer=���º�汾�ţ�completeUrl=���������ص�ַ��forceUpdate=�Ƿ�ǿ�Ƹ���(yes/no)��visible=ǰ̨�Ƿ�ɼ�(yes/no)��command=����ǰ��ִ������
//����<3>��buffer��������
//����<4>��bufferLen���������ߴ�
//======================================================
using hwd_getSoftVersionInfo_t = bool(*)(const char* version, const char* name, char* buffer, int bufferLen);
hwd_getSoftVersionInfo_t hwd_getSoftVersionInfo_o = nullptr;
bool hwd_getSoftVersionInfo(const char* version, const char* name, char* buffer, int bufferLen)
{
	std::cout << "call hwd_getSoftVersionInfo" << std::endl;
	return hwd_getSoftVersionInfo_o(version,name,buffer,bufferLen);
}

//======================================================
//�������ƣ�hwd_getSoftPara
//�������ͣ�bool 
//����˵���������ύ����,��������Զ��峣����ָ���ڵ��ֵ,ֻ���û�������½,�Ż᷵�ش�ֵ,����û�����,��"�����ڵ�½",��ôҲ�᷵�ش�ֵ(Ҳ����������½).ע��,��ʹ�ô�����,���뱣֤����Զ��峣��Ϊ��׼JSON��ʽ
//����<1>��name���� : ����Զ��峣��Ϊ {"�ύ��ַ":"xxx.com","version":"1.0"},�� : hwd_getSoftPara("�ύ��ַ"); ����:xxx.com
//����<2>��buffer������ֵ������
//����<3>��bufferLen���������ߴ�
//======================================================
using hwd_getSoftPara_t = bool(*)(const char* name, char* buffer, int bufferLen);
hwd_getSoftPara_t hwd_getSoftPara_o = nullptr;
bool hwd_getSoftPara(const char* name, char* buffer, int bufferLen)
{
	std::cout << "call hwd_getSoftPara" << std::endl;
	return hwd_getSoftPara_o(name,buffer,bufferLen);
}

//======================================================
//�������ƣ�hwd_getCaptchaImg
//�������ͣ�bool 
//����˵������ȡ��֤��.
//����<1>��buffer������ֵ������
//����<2>��bufferLen���������ߴ�
//======================================================
using hwd_getCaptchaImg_t = bool(*)(char* buffer, int bufferLen);
hwd_getCaptchaImg_t hwd_getCaptchaImg_o = nullptr;
bool hwd_getCaptchaImg(char* buffer, int bufferLen)
{
	std::cout << "call hwd_getCaptchaImg" << std::endl;
	return hwd_getCaptchaImg_o(buffer,bufferLen);
}

//======================================================
//�������ƣ�hwd_getCaptchaImg
//�������ͣ�bool 
//����˵������ȡ��֤�룬���ر����ļ���.
//����<1>��buffer������ֵ������
//����<2>��bufferLen���������ߴ�
//======================================================
using hwd_getCaptchaImgFile_t = bool(*)(char* buffer, int bufferLen);
hwd_getCaptchaImgFile_t hwd_getCaptchaImgFile_o = nullptr;
bool hwd_getCaptchaImgFile(char* buffer, int bufferLen)
{
	std::cout << "call hwd_getCaptchaImgFile" << std::endl;
	return hwd_getCaptchaImgFile_o(buffer, bufferLen);
}

//======================================================
//�������ƣ�hwd_getMachineCode
//�������ͣ�bool 
//����˵������ȡ������.
//����<1>��buffer������ֵ������
//����<2>��bufferLen���������ߴ�
//======================================================
using hwd_getMachineCode_t = bool(*)(char* buffer, int bufferLen);
hwd_getMachineCode_t hwd_getMachineCode_o = nullptr;
bool hwd_getMachineCode(char* buffer, int bufferLen)
{
	std::cout << "call hwd_getMachineCode" << std::endl;
	return hwd_getMachineCode_o(buffer, bufferLen);
}

//======================================================
//�������ƣ�hwd_reg
//�������ͣ�bool 
//����˵����ע��ͨ��֤.
//����<1>��username��ע���û���
//����<2>��password��ע������
//����<3>��email��������,ȡ������Ψһ;��
//����<4>��referrer���Ƽ����˺�,�ɿ�
//����<5>��code����֤��,��� hwd_getSoftInfo("captcha") �а��� "captcha_reg" , ����Ҫ��д��֤��,���������.
//======================================================
using hwd_reg_t = bool(*)(const char* username, const char* password, const char* email, const char* referrer, const char* code);
	hwd_reg_t hwd_reg_o = nullptr;
bool hwd_reg(const char* username, const char* password, const char* email, const char* referrer, const char* code)
{
	std::cout << "call hwd_reg" << std::endl;
	return hwd_reg_o(username,password,email,referrer,code);
}

//======================================================
//�������ƣ�hwd_sendMail
//�������ͣ�bool 
//����˵�����������������ʼ�.
//����<1>��username���û���
//����<2>��mail��������
//����<3>��code����֤��,��� hwd_getSoftInfo("captcha") �а��� "captcha_repwd" , ����Ҫ��д��֤��,���������.
//======================================================
using hwd_sendMail_t = bool(*)(const char* username, const char* email, const char* code);
	hwd_sendMail_t hwd_sendMail_o = nullptr;
bool hwd_sendMail(const char* username, const char* email, const char* code)
{
	std::cout << "call hwd_sendMail" << std::endl;
	return hwd_sendMail_o(username,email,code);
}

//======================================================
//�������ƣ�hwd_resetPwd
//�������ͣ�bool 
//����˵�����޸�����.
//����<1>��username���û���
//����<2>��password��������
//����<3>��mailcode���ʼ���֤��
//����<4>��code����֤��,��� hwd_getSoftInfo("captcha") �а��� "captcha_repwd" , ����Ҫ��д��֤��,���������.
//======================================================
using hwd_resetPwd_t = bool(*)(const char* username, const char* password, const char* mailcode, const char* code);
	hwd_resetPwd_t hwd_resetPwd_o = nullptr;
bool hwd_resetPwd(const char* username, const char* password, const char* mailcode, const char* code)
{
	std::cout << "call hwd_resetPwd" << std::endl;
	return hwd_resetPwd_o(username,password,mailcode,code);
}

//======================================================
//�������ƣ�hwd_recharge
//�������ͣ�bool 
//����˵�����û���ֵ.
//����<1>��user������ֵ���û���
//����<2>��cardnum����ֵ����
//����<3>��code����֤��,��� hwd_getSoftInfo("captcha") �а��� "captcha_recharge" , ����Ҫ��д��֤��,���������
//======================================================
using hwd_recharge_t = bool(*)(const char* user, const char* cardnum, const char* code);
	hwd_recharge_t hwd_recharge_o = nullptr;
bool hwd_recharge(const char* user, const char* cardnum, const char* code)
{
	std::cout << "call hwd_recharge" << std::endl;
	return hwd_recharge_o(user,cardnum,code);
}

//======================================================
//�������ƣ�hwd_addBlackList
//�������ͣ�bool 
//����˵������Ӻ�����.
//����<1>��code������������,������IP��ַ�������,IP��ַ:��ֹһ�з���(������վ),������:��ֹ�ͻ��˷���(��������վ,��Ϊ��վ��ȡ����������,�޷��ж�.)
//����<2>��remark����Ӻ���������
//======================================================
using hwd_addBlackList_t = bool(*)(const char* code, const char* remark);
	hwd_addBlackList_t hwd_addBlackList_o = nullptr;
bool hwd_addBlackList(const char* code, const char* remark)
{
	std::cout << "call hwd_addBlackList" << std::endl;
	return hwd_addBlackList_o(code,remark);
}

//======================================================
//�������ƣ�hwd_login
//�������ͣ�bool 
//����˵�����û���¼.
//����<1>��username���˺�����ģʽΪ��¼�˺�,��ֵ����¼Ϊ����.
//����<2>��password���˺�����ģʽΪ��¼����,��ֵ����¼������д.
//����<3>��code����֤��,��� hwd_getSoftInfo("captcha") �а��� "captcha_login" , ����Ҫ��д��֤��,���������.
//����<4>��client_version���ͻ��˰汾�ţ������ֵ���ں�̨�������û�������ʾ�����û��ͻ��˰汾��.
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
//�������ƣ�hwd_getUserInfo
//�������ͣ�bool 
//����˵������ȡ��¼�û���Ϣ,�����ύ������,����ָ���û�����.
//����<1>��name��username=�û���,password=����,token=��¼token(����У���¼״̬),auth=��¼����,endtime=����ʱ��,point=�������,balance=�˻����,para=�û��Զ�������,bind=�û�����Ϣ
//����<2>��buffer������ֵ������
//����<3>��bufferLen���������ߴ�
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
//�������ƣ�hwd_getUserPara
//�������ͣ�bool 
//����˵���������ύ����,�����û��Զ��峣����ָ���ڵ��ֵ,ֻ���û�������½��δ����/�е���,�Ż᷵�ش�ֵ.ע��,��ʹ�ô�����,���뱣֤�û��Զ��峣��Ϊ��׼JSON��ʽ
//����<1>��name���� : �û��Զ��峣��Ϊ {"�汾":"��ͨ��","�߼�����":"ON"},�� : hwd_getUserPara("�汾"); ����:��ͨ��
//����<2>��buffer������ֵ������
//����<3>��bufferLen���������ߴ�
//======================================================
using hwd_getUserPara_t = bool(*)(const char* name, char* buffer, int bufferLen);
	hwd_getUserPara_t hwd_getUserPara_o = nullptr;
bool hwd_getUserPara(const char* name, char* buffer, int bufferLen)
{
	std::cout << "call hwd_getUserPara" << std::endl;
	return hwd_getUserPara_o(name,buffer,bufferLen);
}

//======================================================
//�������ƣ�hwd_deductPoint
//�������ͣ�bool 
//����˵�����۵�,�Ƶ�ģʽ����.
//����<1>��point���۳�����,��СΪ1��
//����<2>��remarks���۵㱸ע,������ں�̨�鿴,�û����ڸ������Ĳ鿴(����"����༭"�п���"��¼�۵���־")
//����<3>��interval���۵���(��λ:��),0Ϊ����,��ÿ�ζ��۵�.���������ָ������ڲ��ظ��۵�,����1��ֻ��һ�ε�,��ô�������86400��,���������̨����:��¼�۵���־().
//�ر�˵����ֻ����ͬ��point��remarks�Ż����,����:hwd_deductPoint(1,"�շ���",86400) �� hwd_deductPoint(30,"�·���",2592000);������������ͻ,��Ϊ�۵������Ϳ۵㱸ע����ͬ.
//======================================================
using hwd_deductPoint_t = bool(*)(int point, const char* remarks, int interval);
	hwd_deductPoint_t hwd_deductPoint_o = nullptr;
bool hwd_deductPoint(int point, const char* remarks, int interval)
{
	std::cout << "call hwd_deductPoint" << std::endl;
	return hwd_deductPoint_o(point,remarks,interval);
}

//======================================================
//�������ƣ�hwd_deductTime
//�������ͣ�bool 
//����˵������ʱ,��ʱģʽ����.
//����<1>��minute���۳�ʱ��,��λ:����,��СΪ1����
//����<2>��remarks����ʱ��ע,������ں�̨�鿴,�û����ڸ������Ĳ鿴(����"����༭"�п���"��¼�۵���־")
//����<3>��interval����ʱ���(��λ:��),0Ϊ����,��ÿ�ζ���ʱ.���������ָ������ڲ��ظ���ʱ,����1��ֻ��һ��ʱ,��ô�������86400��,���������̨����:��¼�۵���־().
//�ر�˵����ֻ����ͬ��minute��remarks�Ż����,����:hwd_deductTime(1,"�շ���",86400) �� hwd_deductTime(30,"�·���",2592000);������������ͻ,��Ϊ��ʱ�����Ϳ�ʱ��ע����ͬ.
//======================================================
using hwd_deductTime_t = bool(*)(int minute, const char* remarks, int interval);
	hwd_deductTime_t hwd_deductTime_o = nullptr;
bool hwd_deductTime(int minute, const char* remarks, int interval)
{
	std::cout << "call hwd_deductTime" << std::endl;
	return hwd_deductTime_o(minute,remarks,interval);
}

//======================================================
//�������ƣ�hwd_deductBalance
//�������ͣ�bool 
//����˵���������,��¼ģʽΪ:�˺����� ʱ��Ч
//����<1>��money���۳����,��λ:Ԫ,��СΪ0.01Ԫ
//����<2>��remarks���۳���ע,������ں�̨�鿴,�û����ڸ������Ĳ鿴(����"����༭"�п���"��¼�۵���־")
//����<3>��interval���۳����(��λ:��),0Ϊ����,��ÿ�ζ��۳�.���������ָ������ڲ��ظ��۳�,����1��ֻ��һ�����,��ô�������86400��,���������̨����:��¼�۵���־().
//�ر�˵����ֻ����ͬ��money��remarks�Ż����,����:hwd_deductBalance(1,"�շ���",86400) �� hwd_deductBalance(33,"�·���",2592000);������������ͻ,��Ϊ�۳������Ϳ۳���ע����ͬ.
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
//�������ƣ�hwd_setUserbind
//�������ͣ�bool 
//����˵�������û�����,���������Ʊ���,����Ϸ�ŵ�.�û���¼�ɹ�״̬��,��ʹ��hwd_getUserInfo("bind")��ȡ�˰�����.
//����<1>��str����д�������,�����޳�������,�������ݼ��ܴ���,����Խ������ʱ��Խ��,��˲���������̫��.
//======================================================
using hwd_setUserbind_t = bool(*)(const char* str);
	hwd_setUserbind_t hwd_setUserbind_o = nullptr;
bool hwd_setUserbind(const char* str)
{
	std::cout << "call hwd_setUserbind" << std::endl;
	return hwd_setUserbind_o(str);
}

//======================================================
//�������ƣ�hwd_bindMachineCode
//�������ͣ�bool 
//����˵�����󶨻�����,�Զ���ָ���˻��󶨱���,���贫�������,�Զ���ȡ,���Ѵﵽ������,��ɾ�����Ȱ󶨵Ļ�����.ת���ʱ�۵��Զ����,��������۳�.
//����<1>��username�����󶨵��û���,���贫�������,�������Զ���ȡ.
//======================================================
using hwd_bindMachineCode_t = bool(*)(const char* username);
	hwd_bindMachineCode_t hwd_bindMachineCode_o = nullptr;
bool hwd_bindMachineCode(const char* username)
{
	std::cout << "call hwd_bindMachineCode" << std::endl;
	return hwd_bindMachineCode_o(username);
}

//======================================================
//�������ƣ�hwd_logout
//�������ͣ�bool 
//����˵�����˳���¼,�����˳�ǰ�ɵ��ô�����,��������������û�״̬,������Ҫ�ȴ�������ͨѶ��,�����ж��û��˳�
//======================================================
using hwd_logout_t = bool(*)();
	hwd_logout_t hwd_logout_o = nullptr;
bool hwd_logout()
{
	std::cout << "call hwd_logout" << std::endl;
	return hwd_logout_o();
}

//======================================================
//�������ƣ�hwd_callPHP
//�������ͣ�bool 
//����˵������̬�����Զ��庯��(PHP�﷨)
//����<1>��name��������,����:function test($a,$b){return $a + $b},������Ϊ:test
//����<2>��para������ֵ,����:function test($a,$b){return $a + $b},����ֵΪ:3,4 �����ָ���ΪӢ�İ�Ƕ���(,)
//����<3>��buffer������ֵ������
//����<4>��bufferLen���������ߴ�
//======================================================
using hwd_callPHP_t = bool(*)(const char* name, const char* para, char* buffer, int bufferLen);
	hwd_callPHP_t hwd_callPHP_o = nullptr;
bool hwd_callPHP(const char* name, const char* para, char* buffer, int bufferLen)
{
	std::cout << "call hwd_callPHP" << std::endl;
	return hwd_callPHP_o(name,para,buffer,bufferLen);
}

//======================================================
//�������ƣ�hwd_getParam
//�������ͣ�bool 
//����˵������ȡ�ƶ˶����Զ��峣��.
//����<1>��type���������ͣ�0=��������Զ��峣����1=�û������Զ��峣��
//����<2>��name��������
//����<3>��buffer������ֵ������
//����<4>��bufferLen���������ߴ�
//======================================================
using hwd_getParam_t = bool(*)(int type, const char* name, char* buffer, int bufferLen);
	hwd_getParam_t hwd_getParam_o = nullptr;
bool hwd_getParam(int type, const char* name, char* buffer, int bufferLen)
{
	std::cout << "call hwd_getParam" << std::endl;
	return hwd_getParam_o(type,name,buffer,bufferLen);
}

//======================================================
//�������ƣ�hwd_getPcMsg
//�������ͣ�bool 
//����˵����ȡ������������û�����,��ʼ��ʱ[hwd_init()]���ý���ͨѶ����Ч.
//����<1>��key��ͨ����Կ�����ʼ���е�ͨ����Կ��ͬ
//����<2>��name���ڵ���:'soft.x'Ϊ�������(x��ʽͬ'hwd_getSoftInfo()'��'name'��ֵ,����soft.version),'user.x'Ϊ�û�����(x��ʽͬ'hwd_getUserInfo()'��'name'��ֵ,����user.endtime),'softpara.x'Ϊȡ����Զ��峣���ڵ�ֵ(xΪ�ڵ���),'userpara.x'Ϊȡ�û��Զ��峣���ڵ�ֵ(xΪ�ڵ���)
//����<3>��buffer������ֵ������
//����<4>��bufferLen���������ߴ�
//======================================================
using hwd_getPcMsg_t = bool(*)(const char* key, const char* name, char* buffer, int bufferLen);
	hwd_getPcMsg_t hwd_getPcMsg_o = nullptr;
bool hwd_getPcMsg(const char* key, const char* name, char* buffer, int bufferLen)
{
	std::cout << "call hwd_getPcMsg" << std::endl;
	return hwd_getPcMsg_o(key,name,buffer,bufferLen);
}

//======================================================
//�������ƣ�hwd_heartbeat
//�������ͣ�bool 
//����˵����������,�����������ͨѶ.��ע��,�����������ֹ���,1.��������,2.ѭ������,�����뿴����<1>˵��.
//����<1>��time����������,��λ:��,Ϊ0�򵥴�����,������0,����С120��,�����,ֻҪ���ù�1��ѭ������,������˳�ǰ����Ч,���Զ�����,��˴�����ʱ��������̨��������е�"����ʱ��"��ͬ.��ʹʹ���Զ�����,Ҳ�ɵ�������hwd_heartbeat(0)���е�������.
//����<2>��loginAuth����¼���ƣ������̿����գ�ʹ�ô����ƿ��������������¼����.
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
//�������ƣ�hwd_loadLoginWindow
//�������ͣ�bool 
//����˵�����������õ�¼����,����ȼ������߿���ʱ��,����ֻ��ר��������,�ظ��Ĺ���������.ʹ�ô�����ǰ�����ʼ��.
//����<1>��version�����ذ汾��,����������汾�Ų�ͬ,������Զ����³���,���Զ����³��򲻴���,���������ַ.
//����<2>��title�����Ϊ��,����ʾ�����.�������,����Ӧ��10��������.
//����<3>��noticeTime������ͣ��ʱ��,-1:����������,0:���Զ��ر�,��0:����ͣ��ʱ��,��λ����.1��=1000����.
//����<4>��menuItem�����ز˵���,1:�ٷ���վ,2:ע���˻�,3:�޸�����,4:�˻���ֵ,5:�ͷ�QQ,�������ʹ��,����:"12345"��:"1234"
//����<5>��autoHeartbeat����¼�ɹ����Ƿ��Զ�����
//======================================================
using hwd_loadLoginWindow_t = bool(*)(const char* version, const char* title, int noticeTime, const char* menuItem, bool autoHeartbeat);
	hwd_loadLoginWindow_t hwd_loadLoginWindow_o = nullptr;
bool hwd_loadLoginWindow(const char* version, const char* title, int noticeTime, const char* menuItem, bool autoHeartbeat)
{
	std::cout << "call hwd_loadLoginWindow" << std::endl;
	return hwd_loadLoginWindow_o(version,title,noticeTime,menuItem,autoHeartbeat);
}
//======================================================
//�������ƣ�hwd_loadRegWindow
//�������ͣ�bool 
//����˵������������ע�ᴰ��,����ȼ������߿���ʱ��,����ֻ��ר��������,�ظ��Ĺ���������.ʹ�ô�����ǰ�����ʼ��.
//======================================================
using hwd_loadRegWindow_t = bool(*)();
	hwd_loadRegWindow_t hwd_loadRegWindow_o = nullptr;
bool hwd_loadRegWindow()
{
	std::cout << "call hwd_loadRegWindow" << std::endl;
	return hwd_loadRegWindow_o();
}
//======================================================
//�������ƣ�hwd_loadRepwdWindow
//�������ͣ�bool 
//����˵�����������ø��ܴ���,����ȼ������߿���ʱ��,����ֻ��ר��������,�ظ��Ĺ���������.ʹ�ô�����ǰ�����ʼ��.
//======================================================
using hwd_loadRepwdWindow_t = bool(*)();
	hwd_loadRepwdWindow_t hwd_loadRepwdWindow_o = nullptr;
bool hwd_loadRepwdWindow()
{
	std::cout << "call hwd_loadRepwdWindow" << std::endl;
	return hwd_loadRepwdWindow_o();
}
//======================================================
//�������ƣ�hwd_loadRechargeWindow
//�������ͣ�bool 
//����˵�����������ó�ֵ����,����ȼ������߿���ʱ��,����ֻ��ר��������,�ظ��Ĺ���������.ʹ�ô�����ǰ�����ʼ��.
//======================================================
using hwd_loadRechargeWindow_t = bool(*)();
hwd_loadRechargeWindow_t hwd_loadRechargeWindow_o = nullptr;
bool hwd_loadRechargeWindow()
{
	std::cout << "call hwd_loadRechargeWindow" << std::endl;
	return hwd_loadRechargeWindow_o();
}
//======================================================
//�������ƣ�hwd_save
//�������ͣ�bool 
//����˵��������д����,�Զ�����"����Ŀ¼\config.dat",���������������,���hwd_read(string name);��ȡ.
//����<1>��name����������
//����<2>��value������ֵ
//======================================================
using hwd_save_t = bool(*)(const char* name, const char* value);
hwd_save_t hwd_save_o = nullptr;
bool hwd_save(const char* name, const char* value)
{
	std::cout << "call hwd_save" << std::endl;
	return hwd_save_o(name,value);
}
//======================================================
//�������ƣ�hwd_read
//�������ͣ�bool 
//����˵�������ٶ�����,�ɶ�ȡhwd_save();����д�µ�����.
//����<1>��name����������
//����<2>��defaultValue��Ĭ�Ϸ���ֵ
//����<3>��buffer������ֵ������
//����<4>��bufferLen���������ߴ�
//======================================================
using hwd_read_t = bool(*)(const char* name, const char* defaultValue, char* buffer, int bufferLen);
	hwd_read_t hwd_read_o = nullptr;
bool hwd_read(const char* name, const char* defaultValue, char* buffer, int bufferLen)
{
	std::cout << "call hwd_read" << std::endl;
	return hwd_read_o(name,defaultValue,buffer,bufferLen);
}
//======================================================
//�������ƣ�hwd_htmlFilter
//�������ͣ�bool 
//����˵�������˵��ַ����е�html��ǩ,������˹����е�html��ǩ.
//����<1>��htmlStr�������˵�htmlԭ�ַ���
//����<2>��buffer������ֵ������
//����<3>��bufferLen���������ߴ�
//======================================================
using hwd_htmlFilter_t = bool(*)(const char* htmlStr, char* buffer, int bufferLen);
	hwd_htmlFilter_t hwd_htmlFilter_o = nullptr;
bool hwd_htmlFilter(const char* htmlStr, char* buffer, int bufferLen)
{
	std::cout << "call hwd_htmlFilter" << std::endl;
	return hwd_htmlFilter_o(htmlStr,buffer,bufferLen);
}

//======================================================
//�������ƣ�hwd_fastCheck
//�������ͣ�bool 
//����˵����������֤,������ʱ�ӵ�,һ��������ٽ�����֤,���ݰ�ȫ��ǰ����,��ֹ��ƭ���.������ֻ������һ��,�������ǰÿ���������Զ�У��һ��.
//����<1>��url����Ȩ����
//����<2>��port����վ�˿�,�ɿ�,Ĭ��Ϊ80�˿�.��֧��3�ֶ˿ں�,80,443,999,80ΪhttpЭ��,443ΪhttpsЭ��,999Ϊhttpָ���˿�,����δ��������ʹ�ô�½������.
//����<3>��webkey�������ܹ���-�û�����-�ҵ���Ȩ �л��
//����<4>��sid�����ID,��ҳ��̨���������ȡ
//����<5>��key��ͨѶ��Կ,��ҳ��̨���������ȡ
//����<6>��softPara������Զ��峣��, ֻҪ�û�δ����, �˴�һ������.����û�����, �뽫��������Զ��峣��д���˴�, ������������֤.Ҳ�����������ʱʹ��.
//����<7>��isDebug���Ƿ��ڵ���ģʽ������,��ʽ����һ��Ϊfalse.
//����<8>��checkDebug�����ֵ���������,0=�޲���,1=�˳�,2=����,ע��,�ڿ���ģʽ������Ϊ0,��ʽ����һ������.�ں˼�������,��20�ַ������ֶ�,����������������������һ����������,�������߼���.����һ�������Żᴥ������.
//======================================================
using hwd_fastCheck_t = bool(*)(const char* url, int port, const char* webkey, const char* sid, const char* key, const char* softPara, bool isDebug, int checkDebug);
hwd_fastCheck_t hwd_fastCheck_o = nullptr;
bool hwd_fastCheck(const char* url, int port, const char* webkey, const char* sid, const char* key, const char* softPara, bool isDebug, int checkDebug)
{
	std::cout << "call hwd_fastCheck" << std::endl;
	return hwd_fastCheck_o(url,  port,  webkey,  sid,  key,  softPara,  isDebug,  checkDebug);
}

//======================================================
//�������ƣ�hwd_getFastInfo
//�������ͣ�bool 
//����˵���������ύ������,������ҳ�����õ��������,���������,�汾��
//����<2>��name��para=����Զ��峣��,clientip=�ͻ���IP
//����<3>��buffer������ֵ������
//����<4>��bufferLen���������ߴ�
//======================================================
using hwd_getFastInfo_t = bool(*)(const char* name, char* buffer, int bufferLen);
	hwd_getFastInfo_t hwd_getFastInfo_o = nullptr;
bool hwd_getFastInfo(const char* name, char* buffer, int bufferLen) {
	std::cout << "call hwd_getFastInfo" << std::endl;
	return hwd_getFastInfo_o(name,  buffer,  bufferLen);
}
//======================================================
//�������ƣ�hwd_getFastPara
//�������ͣ�bool 
//����˵����������֤ͨ����,�����ύ����,���ؿ����Զ��峣����ָ���ڵ��ֵ,ע��,��ʹ�ô�����,���뱣֤�����Զ��峣��Ϊ��׼JSON��ʽ,������ʹ��hwd_getFastInfo(); ��ȡ���ݺ����д���.
//����<1>��name���� : ����Զ��峣��Ϊ {"�ύ��ַ":"xxx.com","version":"1.0"},�� : hwd_getFastPara("�ύ��ַ"); ����:xxx.com
//����<2>��buffer������ֵ������
//����<3>��bufferLen���������ߴ�
//======================================================
using hwd_getFastPara_t = bool(*)(const char* name, char* buffer, int bufferLen);
	hwd_getFastPara_t hwd_getFastPara_o = nullptr;
bool hwd_getFastPara(const char* name, char* buffer, int bufferLen) {
	std::cout << "call hwd_getFastPara" << std::endl;
	return hwd_getFastPara_o(name, buffer, bufferLen);
}
//======================================================
//�������ƣ�hwd_blueSky
//�������ͣ�bool 
//����˵������ɫ���,���������.
//======================================================
using hwd_blueSky_t = bool(*)();
	hwd_blueSky_t hwd_blueSky_o = nullptr;
bool hwd_blueSky() {
	std::cout << "call hwd_blueSky" << std::endl;
	return hwd_blueSky_o();
}
//======================================================
//�������ƣ�hwd_getFileMD5
//�������ͣ�bool 
//����˵������ȡ�ļ�MD5ֵ
//����<1>��filename����ȡMD5ֵ�����ļ�·��
//����<2>��buffer������ֵ������
//����<3>��bufferLen���������ߴ�
//======================================================
using hwd_getFileMD5_t = bool(*)(const char* filename, char* buffer, int bufferLen);
hwd_getFileMD5_t hwd_getFileMD5_o = nullptr;
bool hwd_getFileMD5(const char* filename, char* buffer, int bufferLen) {
	std::cout << "call hwd_getFileMD5" << std::endl;
	return hwd_getFileMD5_o(filename,  buffer,  bufferLen);
}


//======================================================
//�������ƣ�hwd_getStrMD5
//�������ͣ�bool 
//����˵������ȡ�ַ���MD5ֵ
//����<1>��str����ȡMD5ֵ���ַ���
//����<2>��buffer������ֵ������
//����<3>��bufferLen���������ߴ�
//======================================================
using hwd_getStrMD5_t = bool(*)(const char* str, char* buffer, int bufferLen);
hwd_getStrMD5_t hwd_getStrMD5_o = nullptr;
bool hwd_getStrMD5(const char* str, char* buffer, int bufferLen) {
	std::cout << "call hwd_getStrMD5" << std::endl;
	return hwd_getStrMD5_o( str, buffer,  bufferLen);
}


//======================================================
//�������ƣ�hwd_getRuningPath
//�������ͣ�bool 
//����˵������ȡ�����̵�����Ŀ¼
//����<1>��buffer������ֵ������
//����<2>��bufferLen���������ߴ�
//======================================================
using hwd_getRuningPath_t = bool(*)(char* buffer, int bufferLen);
hwd_getRuningPath_t hwd_getRuningPath_o = nullptr;
bool hwd_getRuningPath(char* buffer, int bufferLen) {
	std::cout << "call hwd_getRuningPath" << std::endl;
	return hwd_getRuningPath_o(buffer, bufferLen);
}


//======================================================
//�������ƣ�hwd_getModulePath
//�������ͣ�bool 
//����˵������ȡ������ģ�������Ŀ¼
//����<1>��buffer������ֵ������
//����<2>��bufferLen���������ߴ�
//======================================================
using hwd_getModulePath_t = bool(*)(char* buffer, int bufferLen);
hwd_getModulePath_t hwd_getModulePath_o = nullptr;
bool hwd_getModulePath(char* buffer, int bufferLen) {
	std::cout << "call hwd_getModulePath" << std::endl;
	return hwd_getModulePath_o(buffer,bufferLen);
}
