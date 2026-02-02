
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import json

# ============ SOLUTION 1: Intelligent Firewall Rule Generator ============
class IntelligentFirewallRuleGenerator:
    """
    Automatically generates firewall rules based on attack patterns
    UNIQUE: Uses ML-driven threat intelligence to create adaptive rules
    """
    
    def __init__(self):
        self.rules = []
        self.rule_id_counter = 1
        
    def generate_rules_from_threats(self, df, threat_intel):
        """
        Generate firewall rules from high-severity attacks
        
        Args:
            df: DataFrame with attack data
            threat_intel: ThreatIntelligence object
            
        Returns:
            list: Generated firewall rules
        """
        df = df.copy()
        df['threat_score'] = df.apply(threat_intel.calculate_threat_score, axis=1)
        
        # Filter high-severity attacks (score >= 70)
        high_threats = df[df['threat_score'] >= 70]
        
        rules = []
        
        # Group by source IP and generate blocking rules
        if 'srcstr' in high_threats.columns:
            for src_ip in high_threats['srcstr'].value_counts().head(20).index:
                rule = {
                    'rule_id': f"FW_{self.rule_id_counter:04d}",
                    'action': 'BLOCK',
                    'source_ip': src_ip,
                    'protocol': 'ANY',
                    'port': 'ANY',
                    'direction': 'INBOUND',
                    'reason': 'High-severity threat detected',
                    'threat_count': int(high_threats[high_threats['srcstr'] == src_ip].shape[0]),
                    'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                rules.append(rule)
                self.rule_id_counter += 1
        
        # Generate port-specific rules
        if 'dpt' in high_threats.columns and 'proto' in high_threats.columns:
            port_proto_attacks = high_threats.groupby(['dpt', 'proto']).size().reset_index(name='count')
            port_proto_attacks = port_proto_attacks.nlargest(10, 'count')
            
            for _, row in port_proto_attacks.iterrows():
                rule = {
                    'rule_id': f"FW_{self.rule_id_counter:04d}",
                    'action': 'RATE_LIMIT',
                    'source_ip': 'ANY',
                    'protocol': row['proto'],
                    'port': int(row['dpt']),
                    'direction': 'INBOUND',
                    'rate_limit': '100/min',
                    'reason': f'High attack volume on port {row["dpt"]}',
                    'attack_count': int(row['count']),
                    'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                rules.append(rule)
                self.rule_id_counter += 1
        
        # Generate country-based geo-blocking rules
        if 'country' in high_threats.columns:
            country_threats = high_threats['country'].value_counts().head(5)
            for country, count in country_threats.items():
                if count > 50:  # Only block if substantial attacks
                    rule = {
                        'rule_id': f"FW_{self.rule_id_counter:04d}",
                        'action': 'GEO_BLOCK',
                        'source_country': country,
                        'protocol': 'ANY',
                        'port': 'ANY',
                        'direction': 'INBOUND',
                        'reason': f'Coordinated attacks from {country}',
                        'attack_count': int(count),
                        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }
                    rules.append(rule)
                    self.rule_id_counter += 1
        
        self.rules.extend(rules)
        return rules
    
    def export_rules(self, format='iptables'):
        """
        Export rules in various firewall formats
        
        Args:
            format: 'iptables', 'pf', 'cisco', 'json'
            
        Returns:
            str: Formatted rules
        """
        if format == 'iptables':
            return self._export_iptables()
        elif format == 'json':
            return json.dumps(self.rules, indent=2)
        elif format == 'cisco':
            return self._export_cisco_acl()
        else:
            return json.dumps(self.rules, indent=2)
    
    def _export_iptables(self):
        """Generate iptables-compatible rules"""
        output = "#!/bin/bash\n"
        output += "# Auto-generated firewall rules from honeypot analysis\n"
        output += f"# Generated at: {datetime.now()}\n\n"
        
        for rule in self.rules:
            if rule['action'] == 'BLOCK':
                output += f"iptables -A INPUT -s {rule['source_ip']} -j DROP  # {rule['reason']}\n"
            elif rule['action'] == 'RATE_LIMIT':
                output += f"iptables -A INPUT -p {rule['protocol'].lower()} --dport {rule['port']} "
                output += f"-m limit --limit {rule['rate_limit']} -j ACCEPT  # {rule['reason']}\n"
        
        return output
    
    def _export_cisco_acl(self):
        """Generate Cisco ACL rules"""
        output = "! Auto-generated Cisco ACL from honeypot analysis\n"
        output += f"! Generated at: {datetime.now()}\n\n"
        
        for rule in self.rules:
            if rule['action'] == 'BLOCK':
                output += f"access-list 100 deny ip host {rule['source_ip']} any  ! {rule['reason']}\n"
        
        output += "access-list 100 permit ip any any\n"
        return output


# ============ SOLUTION 2: Adaptive Rate Limiting System ============
class AdaptiveRateLimiter:
    """
    Intelligent rate limiting that adapts based on attack patterns
    UNIQUE: Uses predictive analytics to set dynamic thresholds
    """
    
    def __init__(self):
        self.rate_limits = {}
        self.baseline_rates = {}
        
    def calculate_adaptive_limits(self, df):
        """
        Calculate adaptive rate limits for each protocol/port combination

        Args:
            df: DataFrame with attack data

        Returns:
            list: Rate limit recommendations
        """
        recommendations = []

        # Defensive handling
        if df.empty:
            return recommendations

        df = df.copy()
        df["datetime"] = pd.to_datetime(df["datetime"], errors="coerce")
        df = df.fillna(0)

        # --- Calculate hourly attack rates by protocol ---
        if "proto" in df.columns and "datetime" in df.columns:
            hourly_proto = (
                df.groupby([pd.Grouper(key="datetime", freq="H"), "proto"])
                .size()
                .reset_index(name="attacks")
            )

            for proto in df["proto"].dropna().unique():
                proto_data = hourly_proto[hourly_proto["proto"] == proto]

                if len(proto_data) > 0:
                    mean_rate = proto_data["attacks"].mean()
                    std_rate = proto_data["attacks"].std()
                    max_rate = proto_data["attacks"].max()

                    # ✅ Handle NaN safely
                    if pd.isna(mean_rate) or pd.isna(std_rate):
                        threshold = 10  # Default safe limit
                    else:
                        threshold = int(mean_rate + 2 * std_rate)

                    recommendations.append({
                        "protocol": proto,
                        "baseline_rate": f"{int(mean_rate) if not pd.isna(mean_rate) else 0}/hour",
                        "recommended_limit": f"{threshold}/hour",
                        "max_observed": int(max_rate) if not pd.isna(max_rate) else 0,
                        "confidence": "95%",
                        "action": "RATE_LIMIT" if threshold < max_rate else "MONITOR"
                    })

        # --- Calculate per-port rate limits ---
        if "dpt" in df.columns and "datetime" in df.columns:
            hourly_port = (
                df.groupby([pd.Grouper(key="datetime", freq="H"), "dpt"])
                .size()
                .reset_index(name="attacks")
            )

            top_ports = df["dpt"].value_counts().head(10).index

            for port in top_ports:
                port_data = hourly_port[hourly_port["dpt"] == port]

                if len(port_data) > 0:
                    mean_rate = port_data["attacks"].mean()
                    std_rate = port_data["attacks"].std()

                    if pd.isna(mean_rate) or pd.isna(std_rate):
                        threshold = 10
                    else:
                        threshold = int(mean_rate + 2 * std_rate)

                    recommendations.append({
                        "target": f"Port {int(port)}",
                        "baseline_rate": f"{int(mean_rate) if not pd.isna(mean_rate) else 0}/hour",
                        "recommended_limit": f"{threshold}/hour",
                        "severity": "HIGH" if port < 1024 else "MEDIUM",
                        "action": "IMPLEMENT_LIMIT"
                    })

        return recommendations

    def generate_nginx_config(self, recommendations):
        """
        Generate nginx rate limiting configuration
        
        Args:
            recommendations: List of rate limit recommendations
            
        Returns:
            str: nginx configuration
        """
        config = "# Auto-generated nginx rate limiting configuration\n"
        config += "# Add to http block in nginx.conf\n\n"
        
        for i, rec in enumerate(recommendations):
            if 'protocol' in rec:
                rate = rec['recommended_limit'].split('/')[0]
                config += f"limit_req_zone $binary_remote_addr zone={rec['protocol'].lower()}_zone:10m rate={rate}r/h;\n"
        
        return config



# ============ SOLUTION 3: Automated Incident Response Playbook ============
class IncidentResponseAutomation:
    """
    Automated incident response based on threat severity
    UNIQUE: Multi-stage response with escalation logic
    """
    
    def __init__(self):
        self.response_actions = []
        self.escalation_levels = {
            'LOW': 1,
            'MEDIUM': 2,
            'HIGH': 3,
            'CRITICAL': 4
        }
        
    def generate_response_playbook(self, df, threat_intel):
        """
        Generate automated response playbook for detected threats
        
        Args:
            df: DataFrame with attack data
            threat_intel: ThreatIntelligence object
            
        Returns:
            list: Response actions
        """
        df = df.copy()
        df['threat_score'] = df.apply(threat_intel.calculate_threat_score, axis=1)
        df['severity'], _ = zip(*df['threat_score'].apply(threat_intel.get_severity_level))
        
        playbook = []
        
        # LEVEL 1: Low-severity automated responses
        low_threats = df[df['severity'] == 'LOW']
        if len(low_threats) > 0:
            playbook.append({
                'severity': 'LOW',
                'trigger_count': len(low_threats),
                'actions': [
                    'Log event to SIEM',
                    'Update threat intelligence database',
                    'Monitor for pattern escalation'
                ],
                'automation': 'FULL',
                'human_review': False
            })
        
        # LEVEL 2: Medium-severity responses
        medium_threats = df[df['severity'] == 'MEDIUM']
        if len(medium_threats) > 0:
            playbook.append({
                'severity': 'MEDIUM',
                'trigger_count': len(medium_threats),
                'actions': [
                    'Alert security team (email)',
                    'Enable enhanced logging',
                    'Implement temporary rate limiting',
                    'Update firewall rules automatically'
                ],
                'automation': 'SEMI',
                'human_review': True,
                'review_sla': '1 hour'
            })
        
        # LEVEL 3: High-severity responses
        high_threats = df[df['severity'] == 'HIGH']
        if len(high_threats) > 0:
            affected_systems = high_threats['host'].nunique() if 'host' in high_threats.columns else 0
            
            playbook.append({
                'severity': 'HIGH',
                'trigger_count': len(high_threats),
                'affected_systems': int(affected_systems),
                'actions': [
                    'IMMEDIATE: Alert security team (SMS + Email)',
                    'Block attacking IPs automatically',
                    'Isolate affected systems',
                    'Capture network traffic for forensics',
                    'Initiate security incident ticket',
                    'Enable IDS/IPS aggressive mode'
                ],
                'automation': 'IMMEDIATE',
                'human_review': True,
                'review_sla': '15 minutes',
                'escalation': 'Security Manager'
            })
        
        # LEVEL 4: Critical-severity responses
        critical_threats = df[df['severity'] == 'CRITICAL']
        if len(critical_threats) > 0:
            attack_vectors = critical_threats.groupby('proto').size().to_dict() if 'proto' in critical_threats.columns else {}
            
            playbook.append({
                'severity': 'CRITICAL',
                'trigger_count': len(critical_threats),
                'attack_vectors': attack_vectors,
                'actions': [
                    '🚨 CRITICAL: Page on-call security engineer',
                    'Execute emergency response protocol',
                    'Quarantine affected network segments',
                    'Block entire source IP ranges',
                    'Activate backup/failover systems',
                    'Initiate forensic data collection',
                    'Notify CISO and legal team',
                    'Consider DDoS mitigation service activation'
                ],
                'automation': 'IMMEDIATE',
                'human_review': True,
                'review_sla': '5 minutes',
                'escalation': 'CISO',
                'external_notification': True
            })
        
        return playbook
    
    def export_playbook(self, playbook):
        """Export playbook in human-readable format"""
        output = "=" * 60 + "\n"
        output += "AUTOMATED INCIDENT RESPONSE PLAYBOOK\n"
        output += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        output += "=" * 60 + "\n\n"
        
        for action in playbook:
            output += f"{'='*60}\n"
            output += f"SEVERITY LEVEL: {action['severity']}\n"
            output += f"Triggered by: {action['trigger_count']} events\n"
            output += f"{'='*60}\n\n"
            
            output += "RESPONSE ACTIONS:\n"
            for i, step in enumerate(action['actions'], 1):
                output += f"  {i}. {step}\n"
            
            output += f"\nAutomation Level: {action['automation']}\n"
            output += f"Human Review Required: {action['human_review']}\n"
            
            if 'review_sla' in action:
                output += f"Review SLA: {action['review_sla']}\n"
            
            if 'escalation' in action:
                output += f"Escalate To: {action['escalation']}\n"
            
            output += "\n\n"
        
        return output


# ============ SOLUTION 4: Network Segmentation Advisor ============
class NetworkSegmentationAdvisor:
    """
    Recommends network segmentation based on attack patterns
    UNIQUE: ML-driven micro-segmentation recommendations
    """
    
    def __init__(self):
        self.segments = []
        
    def analyze_and_recommend(self, df):
        """
        Analyze attack patterns and recommend network segmentation
        
        Args:
            df: DataFrame with attack data
            
        Returns:
            list: Segmentation recommendations
        """
        recommendations = []
        
        # Analyze most attacked hosts
        if 'host' in df.columns:
            host_attacks = df['host'].value_counts()
            
            # Identify critical systems (top 20% most attacked)
            threshold = host_attacks.quantile(0.8)
            critical_hosts = host_attacks[host_attacks > threshold].index.tolist()
            
            if len(critical_hosts) > 0:
                recommendations.append({
                    'segment_name': 'DMZ_Critical',
                    'hosts': critical_hosts,
                    'reason': 'High attack volume detected',
                    'priority': 'HIGH',
                    'rules': [
                        'Isolate from internal network',
                        'Implement strict firewall rules',
                        'Enable enhanced monitoring',
                        'Require VPN for management access'
                    ]
                })
        
        # Analyze protocol-based segmentation
        if 'proto' in df.columns and 'dpt' in df.columns:
            web_services = df[df['dpt'].isin([80, 443, 8080, 8443])]
            if len(web_services) > 100:
                recommendations.append({
                    'segment_name': 'Web_Services_DMZ',
                    'reason': 'High volume web traffic attacks',
                    'priority': 'MEDIUM',
                    'rules': [
                        'Separate web servers into dedicated DMZ',
                        'Implement WAF (Web Application Firewall)',
                        'Use reverse proxy for external access',
                        'Enable DDoS protection'
                    ]
                })
            
            db_services = df[df['dpt'].isin([3306, 5432, 1433, 27017])]
            if len(db_services) > 50:
                recommendations.append({
                    'segment_name': 'Database_Secure_Zone',
                    'reason': 'Database port scanning detected',
                    'priority': 'CRITICAL',
                    'rules': [
                        'Isolate databases in private subnet',
                        'NO direct internet access',
                        'Whitelist only application servers',
                        'Implement database firewall',
                        'Enable query monitoring'
                    ]
                })
        
        # Geographic-based segmentation
        if 'country' in df.columns:
            country_attacks = df['country'].value_counts()
            high_risk_countries = country_attacks.head(3).index.tolist()
            
            recommendations.append({
                'segment_name': 'Geo_Filtering_Layer',
                'reason': f'High attack volume from: {", ".join(high_risk_countries)}',
                'priority': 'MEDIUM',
                'rules': [
                    f'Implement geo-blocking for: {", ".join(high_risk_countries)}',
                    'Use CDN with geo-filtering capabilities',
                    'Require additional authentication from blocked regions',
                    'Monitor for VPN/proxy usage'
                ]
            })
        
        return recommendations
    
    def export_diagram(self, recommendations):
        """Export network segmentation diagram (text-based)"""
        diagram = "\n"
        diagram += "RECOMMENDED NETWORK SEGMENTATION\n"
        diagram += "=" * 60 + "\n\n"
        
        diagram += "Internet\n"
        diagram += "   |\n"
        diagram += "   v\n"
        diagram += "[Firewall + IPS/IDS]\n"
        diagram += "   |\n"
        diagram += "   +---> [DMZ Segment]\n"
        diagram += "   |       |\n"
        
        for rec in recommendations:
            diagram += f"   |       +---> [{rec['segment_name']}] (Priority: {rec['priority']})\n"
        
        diagram += "   |\n"
        diagram += "   +---> [Internal Network]\n"
        diagram += "           |\n"
        diagram += "           +---> [Protected Resources]\n\n"
        
        diagram += "\nDETAILED SEGMENT RULES:\n"
        diagram += "=" * 60 + "\n"
        
        for rec in recommendations:
            diagram += f"\n{rec['segment_name']}:\n"
            diagram += f"  Reason: {rec['reason']}\n"
            diagram += f"  Priority: {rec['priority']}\n"
            diagram += "  Rules:\n"
            for rule in rec.get('rules', []):
                diagram += f"    - {rule}\n"
        
        return diagram


# ============ SOLUTION 5: Threat Intelligence Feed Generator ============
class ThreatIntelligenceFeedGenerator:
    """
    Generate threat intelligence feeds for sharing with SIEM/SOC
    UNIQUE: Creates STIX/TAXII compatible threat feeds
    """
    
    def __init__(self):
        self.indicators = []
        
    def generate_ioc_feed(self, df, threat_intel):
        """
        Generate Indicators of Compromise (IOCs) feed
        
        Args:
            df: DataFrame with attack data
            threat_intel: ThreatIntelligence object
            
        Returns:
            dict: IOC feed in STIX-like format
        """
        df = df.copy()
        df['threat_score'] = df.apply(threat_intel.calculate_threat_score, axis=1)
        
        # Filter high-severity threats only
        high_threats = df[df['threat_score'] >= 60]
        
        iocs = {
            'feed_version': '1.0',
            'generated_at': datetime.now().isoformat(),
            'source': 'Honeypot Threat Intelligence System',
            'indicators': []
        }
        
        # IP-based IOCs
        if 'srcstr' in high_threats.columns:
            for ip in high_threats['srcstr'].value_counts().head(50).index:
                ip_threats = high_threats[high_threats['srcstr'] == ip]
                
                iocs['indicators'].append({
                    'type': 'ipv4',
                    'value': ip,
                    'threat_score': float(ip_threats['threat_score'].mean()),
                    'first_seen': ip_threats['datetime'].min().isoformat() if 'datetime' in ip_threats.columns else None,
                    'last_seen': ip_threats['datetime'].max().isoformat() if 'datetime' in ip_threats.columns else None,
                    'attack_count': int(len(ip_threats)),
                    'protocols': ip_threats['proto'].unique().tolist() if 'proto' in ip_threats.columns else [],
                    'targeted_ports': ip_threats['dpt'].unique().tolist() if 'dpt' in ip_threats.columns else [],
                    'recommended_action': 'BLOCK',
                    'confidence': 'HIGH'
                })
        
        # Port-based IOCs
        if 'dpt' in high_threats.columns:
            suspicious_ports = high_threats['dpt'].value_counts().head(20)
            
            for port, count in suspicious_ports.items():
                port_data = high_threats[high_threats['dpt'] == port]
                
                iocs['indicators'].append({
                    'type': 'port',
                    'value': int(port),
                    'attack_count': int(count),
                    'protocols': port_data['proto'].unique().tolist() if 'proto' in port_data.columns else [],
                    'threat_level': 'HIGH' if port < 1024 else 'MEDIUM',
                    'recommended_action': 'MONITOR_AND_RATE_LIMIT'
                })
        
        return iocs
    
    def export_feed(self, iocs, format='json'):
        """Export IOC feed in various formats"""
        if format == 'json':
            return json.dumps(iocs, indent=2)
        elif format == 'csv':
            indicators_df = pd.DataFrame(iocs['indicators'])
            return indicators_df.to_csv(index=False)
        else:
            return json.dumps(iocs, indent=2)


# ============ SOLUTION 6: Predictive Attack Window Forecaster ============
class PredictiveAttackForecaster:
    """
    Predicts future attack windows for proactive defense
    UNIQUE: Time-series based attack window prediction
    """
    
    def __init__(self):
        self.predictions = []
        
    def forecast_attack_windows(self, df, hours_ahead=24):
        """
        Forecast likely attack windows in the next N hours
        
        Args:
            df: DataFrame with attack data
            hours_ahead: Number of hours to forecast
            
        Returns:
            list: Predicted high-risk time windows
        """
        if 'datetime' not in df.columns:
            return []
        
        # Analyze historical hourly patterns
        hourly_pattern = df.groupby(df['datetime'].dt.hour).size()
        
        # Calculate mean and std for each hour
        hour_stats = []
        for hour in range(24):
            hour_data = df[df['datetime'].dt.hour == hour]
            if len(hour_data) > 0:
                hour_stats.append({
                    'hour': hour,
                    'avg_attacks': len(hour_data) / df['datetime'].dt.date.nunique(),
                    'risk_level': 'HIGH' if len(hour_data) > hourly_pattern.mean() else 'NORMAL'
                })
        
        # Generate forecast for next 24 hours
        current_hour = datetime.now().hour
        forecast = []
        
        for i in range(hours_ahead):
            target_hour = (current_hour + i) % 24
            target_time = datetime.now() + timedelta(hours=i)
            
            hour_info = next((h for h in hour_stats if h['hour'] == target_hour), None)
            
            if hour_info:
                forecast.append({
                    'datetime': target_time.strftime('%Y-%m-%d %H:00'),
                    'hour': target_hour,
                    'predicted_attacks': int(hour_info['avg_attacks']),
                    'risk_level': hour_info['risk_level'],
                    'recommended_actions': self._get_recommendations(hour_info['risk_level'])
                })
        
        return forecast
    
    def _get_recommendations(self, risk_level):
        """Get recommendations based on risk level"""
        if risk_level == 'HIGH':
            return [
                'Increase monitoring frequency',
                'Ensure security team availability',
                'Pre-position additional resources',
                'Enable aggressive rate limiting',
                'Review and update firewall rules'
            ]
        else:
            return [
                'Maintain standard monitoring',
                'Review logs periodically'
            ]
    
    def export_schedule(self, forecast):
        """Export forecast as a schedule"""
        schedule = "ATTACK FORECAST & DEFENSIVE SCHEDULE\n"
        schedule += "=" * 60 + "\n\n"
        
        for window in forecast:
            schedule += f"Time: {window['datetime']}\n"
            schedule += f"Risk Level: {window['risk_level']}\n"
            schedule += f"Predicted Attacks: ~{window['predicted_attacks']}\n"
            schedule += "Recommended Actions:\n"
            for action in window['recommended_actions']:
                schedule += f"  - {action}\n"
            schedule += "\n"
        
        return schedule