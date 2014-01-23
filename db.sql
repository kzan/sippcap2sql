CREATE DATABASE sip_traffic DEFAULT CHARACTER SET utf8;
USE sip_traffic;

CREATE TABLE IF NOT EXISTS `dump_etalon` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ts_sec` int(11) unsigned NOT NULL,
  `ts_usec` int(11) NOT NULL,
  `ip_source` char(15) COLLATE utf8_bin NOT NULL,
  `ip_dest` char(15) COLLATE utf8_bin NOT NULL,
  `udp_source_port` int(11) NOT NULL,
  `udp_dest_port` int(11) NOT NULL,
  `dgram_size` int(11) NOT NULL,
  `sip_method` char(10) COLLATE utf8_bin DEFAULT NULL,
  `sip_status` int(11) unsigned DEFAULT NULL,
  `sip_reason` varchar(255) COLLATE utf8_bin DEFAULT NULL,
  `user_agent` varchar(255) COLLATE utf8_bin DEFAULT NULL,
  `callid` char(100) COLLATE utf8_bin NOT NULL,
  `sip_message` text COLLATE utf8_bin,
  `uri` char(100) COLLATE utf8_bin DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_bin AVG_ROW_LENGTH=661;

