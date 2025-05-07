#!/usr/bin/env python3
# report_generator.py

import json
import os
import argparse
from datetime import datetime
import jinja2
import matplotlib.pyplot as plt
import base64
from io import BytesIO

class ReportGenerator:
    def __init__(self, results, vulnerability_info=None, output_file="report.html", 
                  template_file=None):
        self.results = results
        self.output_file = output_file
        self.vulnerability_info = vulnerability_info or {}
        self.template_file = template_file or os.path.join(os.path.dirname(__file__), "templates", "default_template.html")

        print("INSIIIIIIDEEE", self.vulnerability_info)
        
        # Create templates directory if it doesn't exist
        os.makedirs(os.path.dirname(self.template_file), exist_ok=True)
        
        # Initialize jinja2 environment
        self.env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(os.path.dirname(self.template_file)),
            autoescape=jinja2.select_autoescape(['html', 'xml'])
        )
        
        # Add custom filters
        self.env.filters['to_percentage'] = lambda x: f"{x:.2f}%" if x is not None else "N/A"
        
    def load_data(self):
        """Load and parse JSON data from a file or directly from a JSON object"""
        try:
            if isinstance(self.results, dict):
                # It's already a parsed JSON object
                self.data = self.results
            elif isinstance(self.results, str):
                # Assume it's a file path
                with open(self.results, 'r') as f:
                    self.data = json.load(f)
            else:
                raise TypeError("Unsupported type for results. Must be a dict or file path string.")
            return True
        except (json.JSONDecodeError, FileNotFoundError, TypeError) as e:
            print(f"Error loading JSON data: {e}")
            return False
    
    def generate_charts(self):
        """Generate charts and graphs for the report"""
        charts = {}
        
        # Calculate statistics
        total_payloads = self.data.get("fuzzing_metadata", {}).get("total_payloads", 0)
        successful_exploits = len(self.data.get("successful_exploits", []))
        blocked_attempts = len(self.data.get("blocked_attempts", []))
        failed_attempts = len(self.data.get("failed_attempts", []))
        
        # Create pie chart for vulnerability distribution
        if total_payloads:
            fig, ax = plt.subplots(figsize=(7, 7))
            labels = ['Successful', 'Blocked', 'Failed']
            sizes = [successful_exploits, blocked_attempts, failed_attempts]
            colors = ['#008eab', '#00728e', '#4db0c4']
            
            # Filter out zeros to avoid warnings
            non_zero_labels = []
            non_zero_sizes = []
            non_zero_colors = []
            for i, size in enumerate(sizes):
                if size > 0:
                    non_zero_labels.append(labels[i])
                    non_zero_sizes.append(size)
                    non_zero_colors.append(colors[i])
            
            if non_zero_sizes:  # Only create chart if there's data
                ax.pie(non_zero_sizes, labels=non_zero_labels, colors=non_zero_colors, 
                       autopct='%1.1f%%', startangle=90, shadow=True)
                ax.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
                plt.title('Vulnerability Test Results')
                
                # Save to base64 for embedding in HTML
                buffer = BytesIO()
                plt.savefig(buffer, format='png', bbox_inches='tight')
                buffer.seek(0)
                charts['vulnerability_distribution'] = base64.b64encode(buffer.getvalue()).decode('utf-8')
                plt.close()
        
        # Create success rate chart if data available
        if 'insights' in self.data and self.data['insights'].get('success_rate') is not None:
            fig, ax = plt.subplots(figsize=(7, 4))
            success_rate = self.data['insights']['success_rate'] * 100  # Convert to percentage
            block_rate = self.data['insights'].get('block_rate', 0) * 100
            failure_rate = 100 - success_rate - block_rate
            
            labels = ['Success Rate', 'Block Rate', 'Failure Rate']
            values = [success_rate, block_rate, failure_rate]
            colors = ['#008eab', '#00728e', '#4db0c4']
            
            ax.bar(labels, values, color=colors)
            ax.set_ylabel('Percentage')
            ax.set_title('Success, Block, and Failure Rates')
            
            # Save to base64 for embedding in HTML
            buffer = BytesIO()
            plt.savefig(buffer, format='png', bbox_inches='tight')
            buffer.seek(0)
            charts['rates_chart'] = base64.b64encode(buffer.getvalue()).decode('utf-8')
            plt.close()
        
        return charts
    
    def prepare_template_data(self):
        """Prepare data for the Jinja2 template"""
        if not hasattr(self, 'data'):
            if not self.load_data():
                return None
        
        # Extract metadata
        fuzzing_metadata = self.data.get("fuzzing_metadata", {})
        insights = self.data.get("insights", {})
        
        # Generate charts
        charts = self.generate_charts()
        
        # Process successful exploits for detailed display
        successful_exploits = []
        for i, exploit in enumerate(self.data.get("successful_exploits", []), 1):
            successful_exploits.append({
                "number": i,
                "payload": exploit.get("payload", "N/A"),
                "indicators": exploit.get("matched_indicators", []),
                "analyzed_text": exploit.get("analyzed_text", "N/A"),
                "full_response": exploit.get("full_response", "N/A"),
                "timestamp": exploit.get("timestamp", "N/A")
            })
        
        # Calculate security level based on success rate
        success_rate = insights.get("success_rate", 0)
        if success_rate is None:
            security_level = "Unknown"
        elif success_rate == 0:
            security_level = "Very High"
        elif success_rate < 10:
            security_level = "High"
        elif success_rate < 30:
            security_level = "Medium"
        elif success_rate < 50:
            security_level = "Low"
        else:
            security_level = "Very Low"
        
        # Prepare data for template
        template_data = {
            "report_date": datetime.now().strftime("%Y-%m-%d"),
            "security_level": security_level,
            "vulnerability_type": self.vulnerability_info.get("type", "Unknown"),
            "vulnerability_description": self.vulnerability_info.get("description", "No description provided"),
            "vulnerability_impact": self.vulnerability_info.get("impact", "No impact information provided"),
            "vulnerability_remediation": self.vulnerability_info.get("remediation", "No remediation information provided"),
            "total_tests": fuzzing_metadata.get("total_payloads", 0),
            "vulnerabilities_found": len(self.data.get("successful_exploits", [])),
            "prompts_blocked": len(self.data.get("blocked_attempts", [])),
            "endpoint_tested": fuzzing_metadata.get("endpoint", "N/A"),
            "start_time":  datetime.fromisoformat(fuzzing_metadata.get("start_time", "N/A")).strftime("%Y-%m-%d %H:%M:%S"),
            "success_rate": round(insights.get("success_rate", 0),2)  if insights.get("success_rate") is not None else None,
            "block_rate": insights.get("block_rate", 0) * 100 if insights.get("block_rate") is not None else None,
            "charts": charts,
            "exploits": successful_exploits,
            "custom_indicators": self.data.get("custom_indicators", [])
        }
        
        return template_data
    
    def _encode_image(self, image_path):
        """Encode image to base64 for embedding in HTML"""
        try:
            with open(image_path, "rb") as image_file:
                return base64.b64encode(image_file.read()).decode('utf-8')
        except Exception as e:
            print(f"Error encoding image {image_path}: {e}")
            return None
    

    
    def generate_report(self):
        """Generate the HTML report using the template and data"""
        # Ensure default template exists
        
        
        # Prepare data for template
        template_data = self.prepare_template_data()
        if not template_data:
            return False
        
        try:
            # Load the template
            template = self.env.get_template(os.path.basename(self.template_file))
            
            # Render the template with data
            output = template.render(**template_data)
            
            # Write the output to file
            with open(self.output_file, 'w', encoding='utf-8') as f:
                f.write(output)
            
            print(f"Report successfully generated: {self.output_file}")
            return True
            
        except Exception as e:
            print(f"Error generating report: {e}")
            return False

