/*
 * Date and Time library.
 */
package org.thothtrust.sc.thetakey.timetool;

import java.sql.Timestamp;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 *
 * @author ThothTrust Pte Ltd.
 */
public class DateTimeUtil {

    public static String getTimestamp() {
        Date currDate = new Date();
        SimpleDateFormat dateFormatter = new SimpleDateFormat("E, y-M-d h:m:s a z");
        return dateFormatter.format(currDate);
    }

    public static Date convertStringTimestamp(String dateString) {
        SimpleDateFormat dateFormatter = new SimpleDateFormat("E, y-M-d h:m:s a z");
        Date date = null;
        try {
            date = dateFormatter.parse(dateString);
        } catch (ParseException ex) {
            // Logger.getLogger(DateTimeUtil.class.getName()).log(Level.SEVERE, null, ex);
        }
        return date;
    }

    public static String convertDateTimestamp(Date date) {
        SimpleDateFormat dateFormatter = new SimpleDateFormat("E, y-M-d h:m:s a z");
        return dateFormatter.format(date);
    }

    public static String unixHexStrFromTimestsamp(Timestamp ts) {
        int timestamp = (int) (ts.getTime() / 1000);
        return BinUtils.toHexString(
                new byte[]{
                    (byte) (timestamp >> 24),
                    (byte) (timestamp >> 16),
                    (byte) (timestamp >> 8),
                    (byte) timestamp
                }
        );
    }
    
    public static byte[] unixHexBytesFromTimestsamp(Timestamp ts) {
        int timestamp = (int) (ts.getTime() / 1000);
        return new byte[]{
                    (byte) (timestamp >> 24),
                    (byte) (timestamp >> 16),
                    (byte) (timestamp >> 8),
                    (byte) timestamp
        };        
    }

}
