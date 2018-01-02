package net.csdn;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sensorsdata.analytics.tools.logagent.Processor;

import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Created by zhengwx on 2017/12/29.
 */
public class NginxAccessLogProcessor implements Processor{

    private final static String LOG_SEPARATOR = "\\|";
    private byte[] buffer = new byte[1024 * 1024];

    private SimpleDateFormat timeLocalDateFormat =
            new SimpleDateFormat("dd/MMM/yyyy:HH:mm:ss Z", Locale.US);
    private ObjectMapper objectMapper = new ObjectMapper();

    /* $remote_addr|$host|$upstream_addr|
       $cookie_UserName|[$time_local]|"$request"|
       $status|$body_bytes_sent|"$http_referer"|
       "$http_user_agent"|$request_time|"$cookie_uuid_tt_dd"|
       "$cookie_dc_session_id"

       Example:

       54.36.98.170|read.csdn.net|172.16.100.161:80|
       -|[07/Oct/2017:19:04:33 +0800]|"GET / HTTP/1.1"|
       302|25737|"-"|
       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36"|
        0.472|"-"|
       "-"
     */

    @Override public String process(String line) throws Exception {
        if(line != null){
            String[] items = line.split(LOG_SEPARATOR);
            if(items.length == 13){
                String requestLine = nginxLogFieldUnEscape(items[5]);

                if(!requestLine.contains("favicon.ico")){
                    String remoteAddr = items[0];
                    String host = items[1];
                    String upstreamAddress = items[2];
                    String cookieUserName = items[3];
                    String timeLocal = items[4].replace("[", "").replace("]", "");
                    String status = items[6];
                    String bodyBytesSent = items[7];
                    String referrer = nginxLogFieldUnEscape(items[8].replace("\"", ""));
                    String userAgent = nginxLogFieldUnEscape(items[9].replace("\"", ""));
                    String requestTime = items[10];
                    String cookieID = items[11].replace("\"", "");
                    String sessionID = items[12].replace("\"", "");

                    // 一条事件类型数据, 用于记录用户访问事件
                    Map<String, Object> eventRecord = new HashMap<>();
                    eventRecord.put("type", "track");
                    // 假设以 ip 作为用户
                    eventRecord.put("distinct_id", cookieID);
                    // 解析 03/Sep/2016:15:45:28 +0800 作为时间发生时间
                    eventRecord.put("time", timeLocalDateFormat.parse(timeLocal).getTime());
                    // 事件名称为 RawPageView
                    eventRecord.put("event", "PageView");

                    // 事件相关属性
                    Map<String, Object> eventRecordProperties = new HashMap<>();
                    eventRecord.put("properties", eventRecordProperties);

                    String request_target = parseRequestLine(requestLine);
                    eventRecordProperties.put("request_line", request_target);
                    eventRecordProperties.put("status_code", Integer.getInteger(status));
                    eventRecordProperties.put("body_bytes_sent", Integer.parseInt(bodyBytesSent));
                    eventRecordProperties.put("referrer", referrer);
                    // 设置 $user_agent, 可以自动解析
                    eventRecordProperties.put("$user_agent", userAgent);
                    // 设置 $ip, 可解析地理位置
                    eventRecordProperties.put("$ip", remoteAddr);
                    eventRecordProperties.put("user_name", cookieUserName);
                    eventRecordProperties.put("session_id", sessionID);
                    eventRecordProperties.put("request_time", Double.valueOf(requestTime));
                    eventRecordProperties.put("upstream_address", upstreamAddress);
                    eventRecordProperties.put("curl", host + request_target);
                    eventRecordProperties.put("host", host);

                    return objectMapper.writeValueAsString(eventRecord);
                }
                else{
                    System.out.println("Meet with: favicon.ico");
                }
            }
            else{
                System.out.println("Invalid line: " + line);
            }
        }
        else{
            System.err.println("Error: empty line");
        }
        return null;
    }

    /**
     * 该函数用于字符串字段解码. nginx 输出日志时会对一些字符进行编码, 以避免冲突
     */
    public String nginxLogFieldUnEscape(String record) {
        int count = 0;
        for (int i = 0; i < record.length(); i++) {
            byte ch;
            if (record.charAt(i) == '\\' && record.charAt(i + 1) == 'x') {
                ch = (byte) Integer.parseInt(record.substring(i + 2, i + 4), 16);
                i += 3;
            } else {
                ch = (byte) record.charAt(i);
            }
            buffer[count++] = ch;
        }
        buffer[count] = 0;
        return new String(buffer, 0, count);
    }

    public String parseRequestLine(String requestLine){
        //"GET / HTTP/1.1"
        if(requestLine != null){
            String[] items = requestLine.split(" ");
            if(items.length == 3){
                return items[1];
            }
        }
        return "/";
    }

}
