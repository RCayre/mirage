'''
This module contains some data structures used by the upper application layers of Bluetooth and Bluetooth Low Energy, and it provides some helpers in order to easily use them.
'''

class PairingMethods:
	'''
	This class provides some helpers in order to manipulate the Security Manager protocol.
	'''
	JUST_WORKS = 1
	PASSKEY_ENTRY = 2
	NUMERIC_COMPARISON = 3

	_PAIRING_METHODS = {
		"DisplayOnly":
				{
					"DisplayOnly":(JUST_WORKS,JUST_WORKS),
					"DisplayYesNo":(JUST_WORKS,JUST_WORKS),
					"KeyboardOnly":(PASSKEY_ENTRY,PASSKEY_ENTRY),
					"NoInputNoOutput":(JUST_WORKS,JUST_WORKS),
					"KeyboardDisplay":(PASSKEY_ENTRY,PASSKEY_ENTRY)
				},
		"DisplayYesNo":
				{
					"DisplayOnly":(JUST_WORKS,JUST_WORKS),
					"DisplayYesNo":(JUST_WORKS,NUMERIC_COMPARISON),
					"KeyboardOnly":(PASSKEY_ENTRY,PASSKEY_ENTRY),
					"NoInputNoOutput":(JUST_WORKS,JUST_WORKS),
					"KeyboardDisplay":(PASSKEY_ENTRY,NUMERIC_COMPARISON)
				},
		"KeyboardOnly":
				{
					"DisplayOnly":(PASSKEY_ENTRY,PASSKEY_ENTRY),
					"DisplayYesNo":(PASSKEY_ENTRY,PASSKEY_ENTRY),
					"KeyboardOnly":(PASSKEY_ENTRY,PASSKEY_ENTRY),
					"NoInputNoOutput":(JUST_WORKS,JUST_WORKS),
					"KeyboardDisplay":(PASSKEY_ENTRY,PASSKEY_ENTRY)
				},
		"NoInputNoOutput":
				{
					"DisplayOnly":(JUST_WORKS,JUST_WORKS),
					"DisplayYesNo":(JUST_WORKS,JUST_WORKS),
					"KeyboardOnly":(JUST_WORKS,JUST_WORKS),
					"NoInputNoOutput":(JUST_WORKS,JUST_WORKS),
					"KeyboardDisplay":(JUST_WORKS,JUST_WORKS)
				},
		"KeyboardDisplay":
				{
					"DisplayOnly":(PASSKEY_ENTRY,PASSKEY_ENTRY),
					"DisplayYesNo":(PASSKEY_ENTRY,NUMERIC_COMPARISON),
					"KeyboardOnly":(PASSKEY_ENTRY,PASSKEY_ENTRY),
					"NoInputNoOutput":(JUST_WORKS,JUST_WORKS),
					"KeyboardDisplay":(PASSKEY_ENTRY,NUMERIC_COMPARISON)
				}
	}
	@classmethod
	def getPairingMethod(cls,secureConnections=False,initiatorInputOutputCapability="NoInputNoOutput",responderInputOutputCapability="NoInputNoOutput"):
		'''
		This method allows to select the right pairing method according to the initiator and responder Input Output Capability.

		:param secureConnections: boolean indicating if the secure connections are in use
		:type secureConnections: bool
		:param initiatorInputOutputCapability: string indicating the initiator Input Output Capability
		:type initiatorInputOutputCapability: str
		:param responderInputOutputCapability: string indicating the responder Input Output Capability
		:type initiatorInputOutputCapability: str
		:return: integer indicating the pairing method selected
		:rtype: int

		.. note::
			The possible values for InputOutputCapability parameters are :

			  * "DisplayOnly"
			  * "DisplayYesNo"
			  * "KeyboardOnly"
			  * "NoInputNoOutput"
			  * "KeyboardDisplay"

		
		:Example:
			>>> PairingMethods.getPairingMethod(
			... secureConnections=False,
			... initiatorInputOutputCapability="NoInputNoOutput",
			... responderInputOutputCapability="NoInputNoOutput")
			1
			>>> PairingMethods.getPairingMethod(
			... secureConnections=True,
			... initiatorInputOutputCapability="DisplayOnly",
			... responderInputOutputCapability="KeyboardOnly")
			2

		'''
		methods = cls._PAIRING_METHODS[initiatorInputOutputCapability][responderInputOutputCapability]
		return methods[1] if secureConnections else methods[0]

def _int2bin(s):
    b = str(s) if s<=1 else bin(s>>1)[2:] + str(s&1)
    return (8-len(b))*"0"+b

class AssignedNumbers:
	'''
	This class provides some helpers to get some specific values used by the Bluetooth and Bluetooth Low Energy protocols.
	'''
	@classmethod
	def getStringsbyFlags(cls,flags):
		'''
		This class method converts some flags contained in BLE Advertisements into a list of human readable strings.
		
		:param flags: flags to convert, separated by "+"
		:type flags: str
		:return: list of human readable strings
		:rtype: list of str

		:Example:

			>>> AssignedNumbers.getStringsbyFlags("limited_disc_mode+simul_le_br_edr_host")
			['LE Limited Discoverable Mode', 'Simultaneous LE and BR/EDR, Host']
		
		'''
		return [ADV_FLAGS[flag] for flag in str(flags).split('+')]

	@classmethod
	def getCompanyByNumber(cls,number):
		'''
		This class method converts a company ID into an human readable name.

		:param number: integer indicating the company ID
		:type number: int
		:return: name of company
		:rtype: str

		:Example:
		
			>>> AssignedNumbers.getCompanyByNumber(12)
			'Digianswer A/S'
			>>> AssignedNumbers.getCompanyByNumber(125)
			'Seers Technology Co., Ltd.'

		'''
		for k,v in COMPANY_ID.items():
			if int(k) == int(number):
				return v
		return None
	@classmethod
	def getNumberByName(cls,name):
		'''
		This class method converts a name into the corresponding assigned number.

		:param name: name to convert
		:type name: str
		:return: assigned number
		:rtype: int

		:Example:

			>>> AssignedNumbers.getNumberByName("Generic Access")
			6144
			>>> AssignedNumbers.getNumberByName("Battery Service")
			6159

		'''
		for k,v in ASSIGNED_NUMBERS.items():
			if v['name']==name:
				return int(k)
		return None
	@classmethod
	def getUTIByName(cls,name):
		'''
		This class method converts a name into the corresponding Uniform Type Identifier.

		:param name: name to convert
		:type name: str
		:return: Uniform Type Identifier
		:rtype: str

		:Example:

			>>> AssignedNumbers.getUTIByName("Generic Access")
			'org.bluetooth.service.generic_access'
			>>> AssignedNumbers.getUTIByName("Battery Service")
			'org.bluetooth.service.battery_service'

		'''
		for k,v in ASSIGNED_NUMBERS.items():
			if v['name']==name:
				return v['uniform_type_identifier']
		return None
	@classmethod
	def getNameByNumber(cls,number):
		'''
		This class method converts an assigned number into the corresponding name.

		:param number: assigned number to convert
		:type number: int
		:return: name
		:rtype: str

		:Example:

			>>> AssignedNumbers.getNameByNumber(6144)
			'Generic Access'
			>>> AssignedNumbers.getNameByNumber(6159)
			'Battery Service'

		'''
		for k,v in ASSIGNED_NUMBERS.items():
			if int(k)==number:
				return v['name']
		return None
	@classmethod
	def getUTIByNumber(cls,number):
		'''
		This class method converts an assigned number into the corresponding Uniform Type Identifier.

		:param number: assigned number to convert
		:type number: int
		:return: Uniform Type Identifier
		:rtype: str

		:Example:

			>>> AssignedNumbers.getUTIByNumber(6144)
			'org.bluetooth.service.generic_access'
			>>> AssignedNumbers.getUTIByNumber(6159)
			'org.bluetooth.service.battery_service'

		'''
		for k,v in ASSIGNED_NUMBERS.items():
			if int(k)==number:
				return v['uniform_type_identifier']
		return None
	@classmethod
	def getNumberByUTI(cls,uti):
		'''
		This class method converts an Uniform Type Identifier into the corresponding assigned number.

		:param uti:  Uniform Type Identifier to convert
		:type uti: str
		:return: assigned number
		:rtype: int

		:Example:

			>>> AssignedNumbers.getNumberByUTI('org.bluetooth.service.generic_access')
			6144
			>>> AssignedNumbers.getNumberByUTI('org.bluetooth.service.battery_service')
			6159

		'''
		for k,v in ASSIGNED_NUMBERS.items():
			if v['uniform_type_identifier']==uti:
				return int(k)
		return None
	@classmethod
	def getNameByUTI(cls,uti):
		'''
		This class method converts an Uniform Type Identifier into the corresponding name.

		:param uti:  Uniform Type Identifier to convert
		:type uti: str
		:return: name
		:rtype: str

		:Example:

			>>> AssignedNumbers.getNameByUTI('org.bluetooth.service.generic_access')
			'Generic Access'
			>>> AssignedNumbers.getNameByUTI('org.bluetooth.service.battery_service')
			'Battery Service'

		'''
		for k,v in ASSIGNED_NUMBERS.items():
			if v['uniform_type_identifier']==uti:
				return v['name']
		return None
	@classmethod
	def getPermissionsByNumber(cls,number):
		'''
		This class method converts an ATT permissions number into an human readable list of permissions.
		
		:param number: ATT permissions number
		:type number: int
		:return: human readable list of permissions
		:rtype: list of str

		:Example:
	
			>>> AssignedNumbers.getPermissionsByNumber(5)
			['Write Without Response', 'Broadcast']
			>>> AssignedNumbers.getPermissionsByNumber(1)
			['Broadcast']
			>>> AssignedNumbers.getPermissionsByNumber(6)
			['Write Without Response', 'Read']

		'''
		permissions,flag = [],_int2bin(number)
		for i in range(8):
			if flag[i]=="1":
				permissions.append(PERMISSIONS[i])
		return permissions

	@classmethod
	def getNumberByPermissions(cls,permissions):
		'''
		This class method converts an human readable list of ATT permissions into an ATT permissions number.
		
		:param permissions: human readable list of permissions 
		:type permissions: list of str
		:return: ATT permissions number
		:rtype: int

		:Example:
	
			>>> AssignedNumbers.getNumberByPermissions(['Write Without Response', 'Broadcast'])
			5
			>>> AssignedNumbers.getNumberByPermissions(['Broadcast'])
			1
			>>> AssignedNumbers.getNumberByPermissions(['Write Without Response', 'Read'])
			6


		'''
		flag = list("00000000")
		for permission in permissions:
			try:
				index = PERMISSIONS.index(permission)
				flag[index] = "1"
			except:
				continue
		return int("".join(flag),2)

ADV_FLAGS = {
	"limited_disc_mode":"LE Limited Discoverable Mode" ,
 	"general_disc_mode":"LE General Discoverable Mode" ,
  	"br_edr_not_supported":"BR/EDR not supported" ,
   	"simul_le_br_edr_ctrl":"Simultaneous LE and BR/EDR, Controller",
	"simul_le_br_edr_host":"Simultaneous LE and BR/EDR, Host",
 	"reserved":"Reserved"
}

PERMISSIONS = [
		 	"Extended Properties",
			"Authenticated Signed Writes",
	      		"Indicate",
	    		"Notify",
	  		"Write",
	  		"Write Without Response",
			"Read",
	    		"Broadcast"
    		]

ASSIGNED_NUMBERS = {
    "6144": {
        "name": "Generic Access",
        "uniform_type_identifier": "org.bluetooth.service.generic_access"
    },
    "6145": {
        "name": "Generic Attribute",
        "uniform_type_identifier": "org.bluetooth.service.generic_attribute"
    },
    "6146": {
        "name": "Immediate Alert",
        "uniform_type_identifier": "org.bluetooth.service.immediate_alert"
    },
    "6147": {
        "name": "Link Loss",
        "uniform_type_identifier": "org.bluetooth.service.link_loss"
    },
    "6148": {
        "name": "Tx Power",
        "uniform_type_identifier": "org.bluetooth.service.tx_power"
    },
    "6149": {
        "name": "Current Time Service",
        "uniform_type_identifier": "org.bluetooth.service.current_time"
    },
    "6150": {
        "name": "Reference Time Update Service",
        "uniform_type_identifier": "org.bluetooth.service.reference_time_update"
    },
    "6151": {
        "name": "Next DST Change Service",
        "uniform_type_identifier": "org.bluetooth.service.next_dst_change"
    },
    "6152": {
        "name": "Glucose",
        "uniform_type_identifier": "org.bluetooth.service.glucose"
    },
    "6153": {
        "name": "Health Thermometer",
        "uniform_type_identifier": "org.bluetooth.service.health_thermometer"
    },
    "6154": {
        "name": "Device Information",
        "uniform_type_identifier": "org.bluetooth.service.device_information"
    },
    "6157": {
        "name": "Heart Rate",
        "uniform_type_identifier": "org.bluetooth.service.heart_rate"
    },
    "6158": {
        "name": "Phone Alert Status Service",
        "uniform_type_identifier": "org.bluetooth.service.phone_alert_status"
    },
    "6159": {
        "name": "Battery Service",
        "uniform_type_identifier": "org.bluetooth.service.battery_service"
    },
    "6160": {
        "name": "Blood Pressure",
        "uniform_type_identifier": "org.bluetooth.service.blood_pressure"
    },
    "6161": {
        "name": "Alert Notification Service",
        "uniform_type_identifier": "org.bluetooth.service.alert_notification"
    },
    "6162": {
        "name": "Human Interface Device",
        "uniform_type_identifier": "org.bluetooth.service.human_interface_device"
    },
    "6163": {
        "name": "Scan Parameters",
        "uniform_type_identifier": "org.bluetooth.service.scan_parameters"
    },
    "6164": {
        "name": "Running Speed and Cadence",
        "uniform_type_identifier": "org.bluetooth.service.running_speed_and_cadence"
    },
    "6165": {
        "name": "Automation IO",
        "uniform_type_identifier": "org.bluetooth.service.automation_io"
    },
    "6166": {
        "name": "Cycling Speed and Cadence",
        "uniform_type_identifier": "org.bluetooth.service.cycling_speed_and_cadence"
    },
    "6168": {
        "name": "Cycling Power",
        "uniform_type_identifier": "org.bluetooth.service.cycling_power"
    },
    "6169": {
        "name": "Location and Navigation",
        "uniform_type_identifier": "org.bluetooth.service.location_and_navigation"
    },
    "6170": {
        "name": "Environmental Sensing",
        "uniform_type_identifier": "org.bluetooth.service.environmental_sensing"
    },
    "6171": {
        "name": "Body Composition",
        "uniform_type_identifier": "org.bluetooth.service.body_composition"
    },
    "6172": {
        "name": "User Data",
        "uniform_type_identifier": "org.bluetooth.service.user_data"
    },
    "6173": {
        "name": "Weight Scale",
        "uniform_type_identifier": "org.bluetooth.service.weight_scale"
    },
    "6174": {
        "name": "Bond Management Service",
        "uniform_type_identifier": "org.bluetooth.service.bond_management"
    },
    "6175": {
        "name": "Continuous Glucose Monitoring",
        "uniform_type_identifier": "org.bluetooth.service.continuous_glucose_monitoring"
    },
    "6176": {
        "name": "Internet Protocol Support Service",
        "uniform_type_identifier": "org.bluetooth.service.internet_protocol_support"
    },
    "6177": {
        "name": "Indoor Positioning",
        "uniform_type_identifier": "org.bluetooth.service.indoor_positioning"
    },
    "6178": {
        "name": "Pulse Oximeter Service",
        "uniform_type_identifier": "org.bluetooth.service.pulse_oximeter"
    },
    "6179": {
        "name": "HTTP Proxy",
        "uniform_type_identifier": "org.bluetooth.service.http_proxy"
    },
    "6180": {
        "name": "Transport Discovery",
        "uniform_type_identifier": "org.bluetooth.service.transport_discovery"
    },
    "6181": {
        "name": "Object Transfer Service",
        "uniform_type_identifier": "org.bluetooth.service.object_transfer"
    },
    "6182": {
        "name": "Fitness Machine",
        "uniform_type_identifier": "org.bluetooth.service.fitness_machine"
    },
    "6183": {
        "name": "Mesh Provisioning Service",
        "uniform_type_identifier": "org.bluetooth.service.mesh_provisioning"
    },
    "6184": {
        "name": "Mesh Proxy Service",
        "uniform_type_identifier": "org.bluetooth.service.mesh_proxy"
    },
    "6185": {
        "name": "Reconnection Configuration",
        "uniform_type_identifier": "org.bluetooth.service.reconnection_configuration"
    },
    "10240": {
        "name": "Primary Service",
        "uniform_type_identifier": "org.bluetooth.attribute.gatt.primary_service_declaration"
    },
    "10241": {
        "name": "Secondary Service",
        "uniform_type_identifier": "org.bluetooth.attribute.gatt.secondary_service_declaration"
    },
    "10242": {
        "name": "Include",
        "uniform_type_identifier": "org.bluetooth.attribute.gatt.include_declaration"
    },
    "10243": {
        "name": "Characteristic Declaration",
        "uniform_type_identifier": "org.bluetooth.attribute.gatt.characteristic_declaration"
    },
    "10496": {
        "name": "Characteristic Extended Properties",
        "uniform_type_identifier": "org.bluetooth.descriptor.gatt.characteristic_extended_properties"
    },
    "10497": {
        "name": "Characteristic User Description",
        "uniform_type_identifier": "org.bluetooth.descriptor.gatt.characteristic_user_description"
    },
    "10498": {
        "name": "Client Characteristic Configuration",
        "uniform_type_identifier": "org.bluetooth.descriptor.gatt.client_characteristic_configuration"
    },
    "10499": {
        "name": "Server Characteristic Configuration",
        "uniform_type_identifier": "org.bluetooth.descriptor.gatt.server_characteristic_configuration"
    },
    "10500": {
        "name": "Characteristic Presentation Format",
        "uniform_type_identifier": "org.bluetooth.descriptor.gatt.characteristic_presentation_format"
    },
    "10501": {
        "name": "Characteristic Aggregate Format",
        "uniform_type_identifier": "org.bluetooth.descriptor.gatt.characteristic_aggregate_format"
    },
    "10502": {
        "name": "Valid Range",
        "uniform_type_identifier": "org.bluetooth.descriptor.valid_range"
    },
    "10503": {
        "name": "External Report Reference",
        "uniform_type_identifier": "org.bluetooth.descriptor.external_report_reference"
    },
    "10504": {
        "name": "Report Reference",
        "uniform_type_identifier": "org.bluetooth.descriptor.report_reference"
    },
    "10505": {
        "name": "Number of Digitals",
        "uniform_type_identifier": "org.bluetooth.descriptor.number_of_digitals"
    },
    "10506": {
        "name": "Value Trigger Setting",
        "uniform_type_identifier": "org.bluetooth.descriptor.value_trigger_setting"
    },
    "10507": {
        "name": "Environmental Sensing Configuration",
        "uniform_type_identifier": "org.bluetooth.descriptor.es_configuration"
    },
    "10508": {
        "name": "Environmental Sensing Measurement",
        "uniform_type_identifier": "org.bluetooth.descriptor.es_measurement"
    },
    "10509": {
        "name": "Environmental Sensing Trigger Setting",
        "uniform_type_identifier": "org.bluetooth.descriptor.es_trigger_setting"
    },
    "10510": {
        "name": "Time Trigger Setting",
        "uniform_type_identifier": "org.bluetooth.descriptor.time_trigger_setting"
    },
    "10752": {
        "name": "Device Name",
        "uniform_type_identifier": "org.bluetooth.characteristic.gap.device_name"
    },
    "10753": {
        "name": "Appearance",
        "uniform_type_identifier": "org.bluetooth.characteristic.gap.appearance"
    },
    "10754": {
        "name": "Peripheral Privacy Flag",
        "uniform_type_identifier": "org.bluetooth.characteristic.gap.peripheral_privacy_flag"
    },
    "10755": {
        "name": "Reconnection Address",
        "uniform_type_identifier": "org.bluetooth.characteristic.gap.reconnection_address"
    },
    "10756": {
        "name": "Peripheral Preferred Connection Parameters",
        "uniform_type_identifier": "org.bluetooth.characteristic.gap.peripheral_preferred_connection_parameters"
    },
    "10757": {
        "name": "Service Changed",
        "uniform_type_identifier": "org.bluetooth.characteristic.gatt.service_changed"
    },
    "10758": {
        "name": "Alert Level",
        "uniform_type_identifier": "org.bluetooth.characteristic.alert_level"
    },
    "10759": {
        "name": "Tx Power Level",
        "uniform_type_identifier": "org.bluetooth.characteristic.tx_power_level"
    },
    "10760": {
        "name": "Date Time",
        "uniform_type_identifier": "org.bluetooth.characteristic.date_time"
    },
    "10761": {
        "name": "Day of Week",
        "uniform_type_identifier": "org.bluetooth.characteristic.day_of_week"
    },
    "10762": {
        "name": "Day Date Time",
        "uniform_type_identifier": "org.bluetooth.characteristic.day_date_time"
    },
    "10763": {
        "name": "Exact Time 100",
        "uniform_type_identifier": "org.bluetooth.characteristic.exact_time_100"
    },
    "10764": {
        "name": "Exact Time 256",
        "uniform_type_identifier": "org.bluetooth.characteristic.exact_time_256"
    },
    "10765": {
        "name": "DST Offset",
        "uniform_type_identifier": "org.bluetooth.characteristic.dst_offset"
    },
    "10766": {
        "name": "Time Zone",
        "uniform_type_identifier": "org.bluetooth.characteristic.time_zone"
    },
    "10767": {
        "name": "Local Time Information",
        "uniform_type_identifier": "org.bluetooth.characteristic.local_time_information"
    },
    "10768": {
        "name": "Secondary Time Zone",
        "uniform_type_identifier": "org.bluetooth.characteristic.secondary_time_zone"
    },
    "10769": {
        "name": "Time with DST",
        "uniform_type_identifier": "org.bluetooth.characteristic.time_with_dst"
    },
    "10770": {
        "name": "Time Accuracy",
        "uniform_type_identifier": "org.bluetooth.characteristic.time_accuracy"
    },
    "10771": {
        "name": "Time Source",
        "uniform_type_identifier": "org.bluetooth.characteristic.time_source"
    },
    "10772": {
        "name": "Reference Time Information",
        "uniform_type_identifier": "org.bluetooth.characteristic.reference_time_information"
    },
    "10773": {
        "name": "Time Broadcast",
        "uniform_type_identifier": "org.bluetooth.characteristic.time_broadcast"
    },
    "10774": {
        "name": "Time Update Control Point",
        "uniform_type_identifier": "org.bluetooth.characteristic.time_update_control_point"
    },
    "10775": {
        "name": "Time Update State",
        "uniform_type_identifier": "org.bluetooth.characteristic.time_update_state"
    },
    "10776": {
        "name": "Glucose Measurement",
        "uniform_type_identifier": "org.bluetooth.characteristic.glucose_measurement"
    },
    "10777": {
        "name": "Battery Level",
        "uniform_type_identifier": "org.bluetooth.characteristic.battery_level"
    },
    "10778": {
        "name": "Battery Power State",
        "uniform_type_identifier": "org.bluetooth.characteristic.battery_power_state"
    },
    "10779": {
        "name": "Battery Level State",
        "uniform_type_identifier": "org.bluetooth.characteristic.battery_level_state"
    },
    "10780": {
        "name": "Temperature Measurement",
        "uniform_type_identifier": "org.bluetooth.characteristic.temperature_measurement"
    },
    "10781": {
        "name": "Temperature Type",
        "uniform_type_identifier": "org.bluetooth.characteristic.temperature_type"
    },
    "10782": {
        "name": "Intermediate Temperature",
        "uniform_type_identifier": "org.bluetooth.characteristic.intermediate_temperature"
    },
    "10783": {
        "name": "Temperature Celsius",
        "uniform_type_identifier": "org.bluetooth.characteristic.temperature_celsius"
    },
    "10784": {
        "name": "Temperature Fahrenheit",
        "uniform_type_identifier": "org.bluetooth.characteristic.temperature_fahrenheit"
    },
    "10785": {
        "name": "Measurement Interval",
        "uniform_type_identifier": "org.bluetooth.characteristic.measurement_interval"
    },
    "10786": {
        "name": "Boot Keyboard Input Report",
        "uniform_type_identifier": "org.bluetooth.characteristic.boot_keyboard_input_report"
    },
    "10787": {
        "name": "System ID",
        "uniform_type_identifier": "org.bluetooth.characteristic.system_id"
    },
    "10788": {
        "name": "Model Number String",
        "uniform_type_identifier": "org.bluetooth.characteristic.model_number_string"
    },
    "10789": {
        "name": "Serial Number String",
        "uniform_type_identifier": "org.bluetooth.characteristic.serial_number_string"
    },
    "10790": {
        "name": "Firmware Revision String",
        "uniform_type_identifier": "org.bluetooth.characteristic.firmware_revision_string"
    },
    "10791": {
        "name": "Hardware Revision String",
        "uniform_type_identifier": "org.bluetooth.characteristic.hardware_revision_string"
    },
    "10792": {
        "name": "Software Revision String",
        "uniform_type_identifier": "org.bluetooth.characteristic.software_revision_string"
    },
    "10793": {
        "name": "Manufacturer Name String",
        "uniform_type_identifier": "org.bluetooth.characteristic.manufacturer_name_string"
    },
    "10794": {
        "name": "IEEE 11073-20601 Regulatory Certification Data List",
        "uniform_type_identifier": "org.bluetooth.characteristic.ieee_11073-20601_regulatory_certification_data_list"
    },
    "10795": {
        "name": "Current Time",
        "uniform_type_identifier": "org.bluetooth.characteristic.current_time"
    },
    "10796": {
        "name": "Magnetic Declination",
        "uniform_type_identifier": "org.bluetooth.characteristic.magnetic_declination"
    },
    "10799": {
        "name": "Position 2D",
        "uniform_type_identifier": "org.bluetooth.characteristic.position_2d"
    },
    "10800": {
        "name": "Position 3D",
        "uniform_type_identifier": "org.bluetooth.characteristic.position_3d"
    },
    "10801": {
        "name": "Scan Refresh",
        "uniform_type_identifier": "org.bluetooth.characteristic.scan_refresh"
    },
    "10802": {
        "name": "Boot Keyboard Output Report",
        "uniform_type_identifier": "org.bluetooth.characteristic.boot_keyboard_output_report"
    },
    "10803": {
        "name": "Boot Mouse Input Report",
        "uniform_type_identifier": "org.bluetooth.characteristic.boot_mouse_input_report"
    },
    "10804": {
        "name": "Glucose Measurement Context",
        "uniform_type_identifier": "org.bluetooth.characteristic.glucose_measurement_context"
    },
    "10805": {
        "name": "Blood Pressure Measurement",
        "uniform_type_identifier": "org.bluetooth.characteristic.blood_pressure_measurement"
    },
    "10806": {
        "name": "Intermediate Cuff Pressure",
        "uniform_type_identifier": "org.bluetooth.characteristic.intermediate_cuff_pressure"
    },
    "10807": {
        "name": "Heart Rate Measurement",
        "uniform_type_identifier": "org.bluetooth.characteristic.heart_rate_measurement"
    },
    "10808": {
        "name": "Body Sensor Location",
        "uniform_type_identifier": "org.bluetooth.characteristic.body_sensor_location"
    },
    "10809": {
        "name": "Heart Rate Control Point",
        "uniform_type_identifier": "org.bluetooth.characteristic.heart_rate_control_point"
    },
    "10810": {
        "name": "Removable",
        "uniform_type_identifier": "org.bluetooth.characteristic.removable"
    },
    "10811": {
        "name": "Service Required",
        "uniform_type_identifier": "org.bluetooth.characteristic.service_required"
    },
    "10812": {
        "name": "Scientific Temperature Celsius",
        "uniform_type_identifier": "org.bluetooth.characteristic.scientific_temperature_celsius"
    },
    "10813": {
        "name": "String",
        "uniform_type_identifier": "org.bluetooth.characteristic.string"
    },
    "10814": {
        "name": "Network Availability",
        "uniform_type_identifier": "org.bluetooth.characteristic.network_availability"
    },
    "10815": {
        "name": "Alert Status",
        "uniform_type_identifier": "org.bluetooth.characteristic.alert_status"
    },
    "10816": {
        "name": "Ringer Control point",
        "uniform_type_identifier": "org.bluetooth.characteristic.ringer_control_point"
    },
    "10817": {
        "name": "Ringer Setting",
        "uniform_type_identifier": "org.bluetooth.characteristic.ringer_setting"
    },
    "10818": {
        "name": "Alert Category ID Bit Mask",
        "uniform_type_identifier": "org.bluetooth.characteristic.alert_category_id_bit_mask"
    },
    "10819": {
        "name": "Alert Category ID",
        "uniform_type_identifier": "org.bluetooth.characteristic.alert_category_id"
    },
    "10820": {
        "name": "Alert Notification Control Point",
        "uniform_type_identifier": "org.bluetooth.characteristic.alert_notification_control_point"
    },
    "10821": {
        "name": "Unread Alert Status",
        "uniform_type_identifier": "org.bluetooth.characteristic.unread_alert_status"
    },
    "10822": {
        "name": "New Alert",
        "uniform_type_identifier": "org.bluetooth.characteristic.new_alert"
    },
    "10823": {
        "name": "Supported New Alert Category",
        "uniform_type_identifier": "org.bluetooth.characteristic.supported_new_alert_category"
    },
    "10824": {
        "name": "Supported Unread Alert Category",
        "uniform_type_identifier": "org.bluetooth.characteristic.supported_unread_alert_category"
    },
    "10825": {
        "name": "Blood Pressure Feature",
        "uniform_type_identifier": "org.bluetooth.characteristic.blood_pressure_feature"
    },
    "10826": {
        "name": "HID Information",
        "uniform_type_identifier": "org.bluetooth.characteristic.hid_information"
    },
    "10827": {
        "name": "Report Map",
        "uniform_type_identifier": "org.bluetooth.characteristic.report_map"
    },
    "10828": {
        "name": "HID Control Point",
        "uniform_type_identifier": "org.bluetooth.characteristic.hid_control_point"
    },
    "10829": {
        "name": "Report",
        "uniform_type_identifier": "org.bluetooth.characteristic.report"
    },
    "10830": {
        "name": "Protocol Mode",
        "uniform_type_identifier": "org.bluetooth.characteristic.protocol_mode"
    },
    "10831": {
        "name": "Scan Interval Window",
        "uniform_type_identifier": "org.bluetooth.characteristic.scan_interval_window"
    },
    "10832": {
        "name": "PnP ID",
        "uniform_type_identifier": "org.bluetooth.characteristic.pnp_id"
    },
    "10833": {
        "name": "Glucose Feature",
        "uniform_type_identifier": "org.bluetooth.characteristic.glucose_feature"
    },
    "10834": {
        "name": "Record Access Control Point",
        "uniform_type_identifier": "org.bluetooth.characteristic.record_access_control_point"
    },
    "10835": {
        "name": "RSC Measurement",
        "uniform_type_identifier": "org.bluetooth.characteristic.rsc_measurement"
    },
    "10836": {
        "name": "RSC Feature",
        "uniform_type_identifier": "org.bluetooth.characteristic.rsc_feature"
    },
    "10837": {
        "name": "SC Control Point",
        "uniform_type_identifier": "org.bluetooth.characteristic.sc_control_point"
    },
    "10838": {
        "name": "Digital",
        "uniform_type_identifier": "org.bluetooth.characteristic.digital"
    },
    "10839": {
        "name": "Digital Output",
        "uniform_type_identifier": "org.bluetooth.characteristic.digital_output"
    },
    "10840": {
        "name": "Analog",
        "uniform_type_identifier": "org.bluetooth.characteristic.analog"
    },
    "10841": {
        "name": "Analog Output",
        "uniform_type_identifier": "org.bluetooth.characteristic.analog_output"
    },
    "10842": {
        "name": "Aggregate",
        "uniform_type_identifier": "org.bluetooth.characteristic.aggregate"
    },
    "10843": {
        "name": "CSC Measurement",
        "uniform_type_identifier": "org.bluetooth.characteristic.csc_measurement"
    },
    "10844": {
        "name": "CSC Feature",
        "uniform_type_identifier": "org.bluetooth.characteristic.csc_feature"
    },
    "10845": {
        "name": "Sensor Location",
        "uniform_type_identifier": "org.bluetooth.characteristic.sensor_location"
    },
    "10846": {
        "name": "PLX Spot-Check Measurement",
        "uniform_type_identifier": "org.bluetooth.characteristic.plx_spot_check_measurement"
    },
    "10847": {
        "name": "PLX Continuous Measurement Characteristic",
        "uniform_type_identifier": "org.bluetooth.characteristic.plx_continuous_measurement"
    },
    "10848": {
        "name": "PLX Features",
        "uniform_type_identifier": "org.bluetooth.characteristic.plx_features"
    },
    "10850": {
        "name": "Pulse Oximetry Control Point",
        "uniform_type_identifier": "org.bluetooth.characteristic.pulse_oximetry_control_point"
    },
    "10851": {
        "name": "Cycling Power Measurement",
        "uniform_type_identifier": "org.bluetooth.characteristic.cycling_power_measurement"
    },
    "10852": {
        "name": "Cycling Power Vector",
        "uniform_type_identifier": "org.bluetooth.characteristic.cycling_power_vector"
    },
    "10853": {
        "name": "Cycling Power Feature",
        "uniform_type_identifier": "org.bluetooth.characteristic.cycling_power_feature"
    },
    "10854": {
        "name": "Cycling Power Control Point",
        "uniform_type_identifier": "org.bluetooth.characteristic.cycling_power_control_point"
    },
    "10855": {
        "name": "Location and Speed Characteristic",
        "uniform_type_identifier": "org.bluetooth.characteristic.location_and_speed"
    },
    "10856": {
        "name": "Navigation",
        "uniform_type_identifier": "org.bluetooth.characteristic.navigation"
    },
    "10857": {
        "name": "Position Quality",
        "uniform_type_identifier": "org.bluetooth.characteristic.position_quality"
    },
    "10858": {
        "name": "LN Feature",
        "uniform_type_identifier": "org.bluetooth.characteristic.ln_feature"
    },
    "10859": {
        "name": "LN Control Point",
        "uniform_type_identifier": "org.bluetooth.characteristic.ln_control_point"
    },
    "10860": {
        "name": "Elevation",
        "uniform_type_identifier": "org.bluetooth.characteristic.elevation"
    },
    "10861": {
        "name": "Pressure",
        "uniform_type_identifier": "org.bluetooth.characteristic.pressure"
    },
    "10862": {
        "name": "Temperature",
        "uniform_type_identifier": "org.bluetooth.characteristic.temperature"
    },
    "10863": {
        "name": "Humidity",
        "uniform_type_identifier": "org.bluetooth.characteristic.humidity"
    },
    "10864": {
        "name": "True Wind Speed",
        "uniform_type_identifier": "org.bluetooth.characteristic.true_wind_speed"
    },
    "10865": {
        "name": "True Wind Direction",
        "uniform_type_identifier": "org.bluetooth.characteristic.true_wind_direction"
    },
    "10866": {
        "name": "Apparent Wind Speed",
        "uniform_type_identifier": "org.bluetooth.characteristic.apparent_wind_speed"
    },
    "10867": {
        "name": "Apparent Wind Direction",
        "uniform_type_identifier": "org.bluetooth.characteristic.apparent_wind_direction"
    },
    "10868": {
        "name": "Gust Factor",
        "uniform_type_identifier": "org.bluetooth.characteristic.gust_factor"
    },
    "10869": {
        "name": "Pollen Concentration",
        "uniform_type_identifier": "org.bluetooth.characteristic.pollen_concentration"
    },
    "10870": {
        "name": "UV Index",
        "uniform_type_identifier": "org.bluetooth.characteristic.uv_index"
    },
    "10871": {
        "name": "Irradiance",
        "uniform_type_identifier": "org.bluetooth.characteristic.irradiance"
    },
    "10872": {
        "name": "Rainfall",
        "uniform_type_identifier": "org.bluetooth.characteristic.rainfall"
    },
    "10873": {
        "name": "Wind Chill",
        "uniform_type_identifier": "org.bluetooth.characteristic.wind_chill"
    },
    "10874": {
        "name": "Heat Index",
        "uniform_type_identifier": "org.bluetooth.characteristic.heat_index"
    },
    "10875": {
        "name": "Dew Point",
        "uniform_type_identifier": "org.bluetooth.characteristic.dew_point"
    },
    "10877": {
        "name": "Descriptor Value Changed",
        "uniform_type_identifier": "org.bluetooth.characteristic.descriptor_value_changed"
    },
    "10878": {
        "name": "Aerobic Heart Rate Lower Limit",
        "uniform_type_identifier": "org.bluetooth.characteristic.aerobic_heart_rate_lower_limit"
    },
    "10879": {
        "name": "Aerobic Threshold",
        "uniform_type_identifier": "org.bluetooth.characteristic.aerobic_threshold"
    },
    "10880": {
        "name": "Age",
        "uniform_type_identifier": "org.bluetooth.characteristic.age"
    },
    "10881": {
        "name": "Anaerobic Heart Rate Lower Limit",
        "uniform_type_identifier": "org.bluetooth.characteristic.anaerobic_heart_rate_lower_limit"
    },
    "10882": {
        "name": "Anaerobic Heart Rate Upper Limit",
        "uniform_type_identifier": "org.bluetooth.characteristic.anaerobic_heart_rate_upper_limit"
    },
    "10883": {
        "name": "Anaerobic Threshold",
        "uniform_type_identifier": "org.bluetooth.characteristic.anaerobic_threshold"
    },
    "10884": {
        "name": "Aerobic Heart Rate Upper Limit",
        "uniform_type_identifier": "org.bluetooth.characteristic.aerobic_heart_rate_upper_limit"
    },
    "10885": {
        "name": "Date of Birth",
        "uniform_type_identifier": "org.bluetooth.characteristic.date_of_birth"
    },
    "10886": {
        "name": "Date of Threshold Assessment",
        "uniform_type_identifier": "org.bluetooth.characteristic.date_of_threshold_assessment"
    },
    "10887": {
        "name": "Email Address",
        "uniform_type_identifier": "org.bluetooth.characteristic.email_address"
    },
    "10888": {
        "name": "Fat Burn Heart Rate Lower Limit",
        "uniform_type_identifier": "org.bluetooth.characteristic.fat_burn_heart_rate_lower_limit"
    },
    "10889": {
        "name": "Fat Burn Heart Rate Upper Limit",
        "uniform_type_identifier": "org.bluetooth.characteristic.fat_burn_heart_rate_upper_limit"
    },
    "10890": {
        "name": "First Name",
        "uniform_type_identifier": "org.bluetooth.characteristic.first_name"
    },
    "10891": {
        "name": "Five Zone Heart Rate Limits",
        "uniform_type_identifier": "org.bluetooth.characteristic.five_zone_heart_rate_limits"
    },
    "10892": {
        "name": "Gender",
        "uniform_type_identifier": "org.bluetooth.characteristic.gender"
    },
    "10893": {
        "name": "Heart Rate Max",
        "uniform_type_identifier": "org.bluetooth.characteristic.heart_rate_max"
    },
    "10894": {
        "name": "Height",
        "uniform_type_identifier": "org.bluetooth.characteristic.height"
    },
    "10895": {
        "name": "Hip Circumference",
        "uniform_type_identifier": "org.bluetooth.characteristic.hip_circumference"
    },
    "10896": {
        "name": "Last Name",
        "uniform_type_identifier": "org.bluetooth.characteristic.last_name"
    },
    "10897": {
        "name": "Maximum Recommended Heart Rate",
        "uniform_type_identifier": "org.bluetooth.characteristic.maximum_recommended_heart_rate"
    },
    "10898": {
        "name": "Resting Heart Rate",
        "uniform_type_identifier": "org.bluetooth.characteristic.resting_heart_rate"
    },
    "10899": {
        "name": "Sport Type for Aerobic and Anaerobic Thresholds",
        "uniform_type_identifier": "org.bluetooth.characteristic.sport_type_for_aerobic_and_anaerobic_thresholds"
    },
    "10900": {
        "name": "Three Zone Heart Rate Limits",
        "uniform_type_identifier": "org.bluetooth.characteristic.three_zone_heart_rate_limits"
    },
    "10901": {
        "name": "Two Zone Heart Rate Limit",
        "uniform_type_identifier": "org.bluetooth.characteristic.two_zone_heart_rate_limit"
    },
    "10902": {
        "name": "VO2 Max",
        "uniform_type_identifier": "org.bluetooth.characteristic.vo2_max"
    },
    "10903": {
        "name": "Waist Circumference",
        "uniform_type_identifier": "org.bluetooth.characteristic.waist_circumference"
    },
    "10904": {
        "name": "Weight",
        "uniform_type_identifier": "org.bluetooth.characteristic.weight"
    },
    "10905": {
        "name": "Database Change Increment",
        "uniform_type_identifier": "org.bluetooth.characteristic.database_change_increment"
    },
    "10906": {
        "name": "User Index",
        "uniform_type_identifier": "org.bluetooth.characteristic.user_index"
    },
    "10907": {
        "name": "Body Composition Feature",
        "uniform_type_identifier": "org.bluetooth.characteristic.body_composition_feature"
    },
    "10908": {
        "name": "Body Composition Measurement",
        "uniform_type_identifier": "org.bluetooth.characteristic.body_composition_measurement"
    },
    "10909": {
        "name": "Weight Measurement",
        "uniform_type_identifier": "org.bluetooth.characteristic.weight_measurement"
    },
    "10910": {
        "name": "Weight Scale Feature",
        "uniform_type_identifier": "org.bluetooth.characteristic.weight_scale_feature"
    },
    "10911": {
        "name": "User Control Point",
        "uniform_type_identifier": "org.bluetooth.characteristic.user_control_point"
    },
    "10912": {
        "name": "Magnetic Flux Density - 2D",
        "uniform_type_identifier": "org.bluetooth.characteristic.Magnetic_flux_density_2D"
    },
    "10913": {
        "name": "Magnetic Flux Density - 3D",
        "uniform_type_identifier": "org.bluetooth.characteristic.Magnetic_flux_density_3D"
    },
    "10914": {
        "name": "Language",
        "uniform_type_identifier": "org.bluetooth.characteristic.language"
    },
    "10915": {
        "name": "Barometric Pressure Trend",
        "uniform_type_identifier": "org.bluetooth.characteristic.barometric_pressure_trend"
    },
    "10916": {
        "name": "Bond Management Control Point",
        "uniform_type_identifier": "org.bluetooth.characteristic.bond_management_control_point"
    },
    "10917": {
        "name": "Bond Management Features",
        "uniform_type_identifier": "org.bluetooth.characteristic.bond_management_feature"
    },
    "10918": {
        "name": "Central Address Resolution",
        "uniform_type_identifier": "org.bluetooth.characteristic.gap.central_address_resolution"
    },
    "10919": {
        "name": "CGM Measurement",
        "uniform_type_identifier": "org.bluetooth.characteristic.cgm_measurement"
    },
    "10920": {
        "name": "CGM Feature",
        "uniform_type_identifier": "org.bluetooth.characteristic.cgm_feature"
    },
    "10921": {
        "name": "CGM Status",
        "uniform_type_identifier": "org.bluetooth.characteristic.cgm_status"
    },
    "10922": {
        "name": "CGM Session Start Time",
        "uniform_type_identifier": "org.bluetooth.characteristic.cgm_session_start_time"
    },
    "10923": {
        "name": "CGM Session Run Time",
        "uniform_type_identifier": "org.bluetooth.characteristic.cgm_session_run_time"
    },
    "10924": {
        "name": "CGM Specific Ops Control Point",
        "uniform_type_identifier": "org.bluetooth.characteristic.cgm_specific_ops_control_point"
    },
    "10925": {
        "name": "Indoor Positioning Configuration",
        "uniform_type_identifier": "org.bluetooth.characteristic.indoor_positioning_configuration"
    },
    "10926": {
        "name": "Latitude",
        "uniform_type_identifier": "org.bluetooth.characteristic.latitude"
    },
    "10927": {
        "name": "Longitude",
        "uniform_type_identifier": "org.bluetooth.characteristic.Longitude"
    },
    "10928": {
        "name": "Local North Coordinate",
        "uniform_type_identifier": "org.bluetooth.characteristic.local_north_coordinate"
    },
    "10929": {
        "name": "Local East Coordinate",
        "uniform_type_identifier": "org.bluetooth.characteristic.local_east_coordinate"
    },
    "10930": {
        "name": "Floor Number",
        "uniform_type_identifier": "org.bluetooth.characteristic.floor_number"
    },
    "10931": {
        "name": "Altitude",
        "uniform_type_identifier": "org.bluetooth.characteristic.altitude"
    },
    "10932": {
        "name": "Uncertainty",
        "uniform_type_identifier": "org.bluetooth.characteristic.uncertainty"
    },
    "10933": {
        "name": "Location Name",
        "uniform_type_identifier": "org.bluetooth.characteristic.location_name"
    },
    "10934": {
        "name": "URI",
        "uniform_type_identifier": "org.bluetooth.characteristic.uri"
    },
    "10935": {
        "name": "HTTP Headers",
        "uniform_type_identifier": "org.bluetooth.characteristic.http_headers"
    },
    "10936": {
        "name": "HTTP Status Code",
        "uniform_type_identifier": "org.bluetooth.characteristic.http_status_code"
    },
    "10937": {
        "name": "HTTP Entity Body",
        "uniform_type_identifier": "org.bluetooth.characteristic.http_entity_body"
    },
    "10938": {
        "name": "HTTP Control Point",
        "uniform_type_identifier": "org.bluetooth.characteristic.http_control_point"
    },
    "10939": {
        "name": "HTTPS Security",
        "uniform_type_identifier": "org.bluetooth.characteristic.https_security"
    },
    "10940": {
        "name": "TDS Control Point",
        "uniform_type_identifier": "org.bluetooth.characteristic.tds_control_point"
    },
    "10941": {
        "name": "OTS Feature",
        "uniform_type_identifier": "org.bluetooth.characteristic.ots_feature"
    },
    "10942": {
        "name": "Object Name",
        "uniform_type_identifier": "org.bluetooth.characteristic.object_name"
    },
    "10943": {
        "name": "Object Type",
        "uniform_type_identifier": "org.bluetooth.characteristic.object_type"
    },
    "10944": {
        "name": "Object Size",
        "uniform_type_identifier": "org.bluetooth.characteristic.object_size"
    },
    "10945": {
        "name": "Object First-Created",
        "uniform_type_identifier": "org.bluetooth.characteristic.object_first_created"
    },
    "10946": {
        "name": "Object Last-Modified",
        "uniform_type_identifier": "org.bluetooth.characteristic.object_last_modified"
    },
    "10947": {
        "name": "Object ID",
        "uniform_type_identifier": "org.bluetooth.characteristic.object_id"
    },
    "10948": {
        "name": "Object Properties",
        "uniform_type_identifier": "org.bluetooth.characteristic.object_properties"
    },
    "10949": {
        "name": "Object Action Control Point",
        "uniform_type_identifier": "org.bluetooth.characteristic.object_action_control_point"
    },
    "10950": {
        "name": "Object List Control Point",
        "uniform_type_identifier": "org.bluetooth.characteristic.object_list_control_point"
    },
    "10951": {
        "name": "Object List Filter",
        "uniform_type_identifier": "org.bluetooth.characteristic.object_list_filter"
    },
    "10952": {
        "name": "Object Changed",
        "uniform_type_identifier": "org.bluetooth.characteristic.object_changed"
    },
    "10953": {
        "name": "Resolvable Private Address Only",
        "uniform_type_identifier": "org.bluetooth.characteristic.resolvable_private_address_only"
    },
    "10956": {
        "name": "Fitness Machine Feature",
        "uniform_type_identifier": "org.bluetooth.characteristic.fitness_machine_feature"
    },
    "10957": {
        "name": "Treadmill Data",
        "uniform_type_identifier": "org.bluetooth.characteristic.treadmill_data"
    },
    "10958": {
        "name": "Cross Trainer Data",
        "uniform_type_identifier": "org.bluetooth.characteristic.cross_trainer_data"
    },
    "10959": {
        "name": "Step Climber Data",
        "uniform_type_identifier": "org.bluetooth.characteristic.step_climber_data"
    },
    "10960": {
        "name": "Stair Climber Data",
        "uniform_type_identifier": "org.bluetooth.characteristic.stair_climber_data"
    },
    "10961": {
        "name": "Rower Data",
        "uniform_type_identifier": "org.bluetooth.characteristic.rower_data"
    },
    "10962": {
        "name": "Indoor Bike Data",
        "uniform_type_identifier": "org.bluetooth.characteristic.indoor_bike_data"
    },
    "10963": {
        "name": "Training Status",
        "uniform_type_identifier": "org.bluetooth.characteristic.training_status"
    },
    "10964": {
        "name": "Supported Speed Range",
        "uniform_type_identifier": "org.bluetooth.characteristic.supported_speed_range"
    },
    "10965": {
        "name": "Supported Inclination Range",
        "uniform_type_identifier": "org.bluetooth.characteristic.supported_inclination_range"
    },
    "10966": {
        "name": "Supported Resistance Level Range",
        "uniform_type_identifier": "org.bluetooth.characteristic.supported_resistance_level_range"
    },
    "10967": {
        "name": "Supported Heart Rate Range",
        "uniform_type_identifier": "org.bluetooth.characteristic.supported_heart_rate_range"
    },
    "10968": {
        "name": "Supported Power Range",
        "uniform_type_identifier": "org.bluetooth.characteristic.supported_power_range"
    },
    "10969": {
        "name": "Fitness Machine Control Point",
        "uniform_type_identifier": "org.bluetooth.characteristic.fitness_machine_control_point"
    },
    "10970": {
        "name": "Fitness Machine Status",
        "uniform_type_identifier": "org.bluetooth.characteristic.fitness_machine_status"
    },
    "11037": {
        "name": "RC Feature",
        "uniform_type_identifier": "org.bluetooth.characteristic.rc_feature"
    },
    "11038": {
        "name": "RC Settings",
        "uniform_type_identifier": "org.bluetooth.characteristic.rc_settings"
    },
    "11039": {
        "name": "Reconnection Configuration Control Point",
        "uniform_type_identifier": "org.bluetooth.characteristic.reconnection_configuration_control_point"
    }
}

COMPANY_ID = {
    "0": "Ericsson Technology Licensing",
    "1": "Nokia Mobile Phones",
    "2": "Intel Corp.",
    "3": "IBM Corp.",
    "4": "Toshiba Corp.",
    "5": "3Com",
    "6": "Microsoft",
    "7": "Lucent",
    "8": "Motorola",
    "9": "Infineon Technologies AG",
    "10": "Qualcomm Technologies International, Ltd. (QTIL)",
    "11": "Silicon Wave",
    "12": "Digianswer A/S",
    "13": "Texas Instruments Inc.",
    "14": "Parthus Technologies Inc.",
    "15": "Broadcom Corporation",
    "16": "Mitel Semiconductor",
    "17": "Widcomm, Inc.",
    "18": "Zeevo, Inc.",
    "19": "Atmel Corporation",
    "20": "Mitsubishi Electric Corporation",
    "21": "RTX Telecom A/S",
    "22": "KC Technology Inc.",
    "23": "Newlogic",
    "24": "Transilica, Inc.",
    "25": "Rohde & Schwarz GmbH & Co. KG",
    "26": "TTPCom Limited",
    "27": "Signia Technologies, Inc.",
    "28": "Conexant Systems Inc.",
    "29": "Qualcomm",
    "30": "Inventel",
    "31": "AVM Berlin",
    "32": "BandSpeed, Inc.",
    "33": "Mansella Ltd",
    "34": "NEC Corporation",
    "35": "WavePlus Technology Co., Ltd.",
    "36": "Alcatel",
    "37": "NXP Semiconductors (formerly Philips Semiconductors)",
    "38": "C Technologies",
    "39": "Open Interface",
    "40": "R F Micro Devices",
    "41": "Hitachi Ltd",
    "42": "Symbol Technologies, Inc.",
    "43": "Tenovis",
    "44": "Macronix International Co. Ltd.",
    "45": "GCT Semiconductor",
    "46": "Norwood Systems",
    "47": "MewTel Technology Inc.",
    "48": "ST Microelectronics",
    "49": "Synopsys, Inc.",
    "50": "Red-M (Communications) Ltd",
    "51": "Commil Ltd",
    "52": "Computer Access Technology Corporation (CATC)",
    "53": "Eclipse (HQ Espana) S.L.",
    "54": "Renesas Electronics Corporation",
    "55": "Mobilian Corporation",
    "56": "Syntronix Corporation",
    "57": "Integrated System Solution Corp.",
    "58": "Matsushita Electric Industrial Co., Ltd.",
    "59": "Gennum Corporation",
    "60": "BlackBerry Limited (formerly Research In Motion)",
    "61": "IPextreme, Inc.",
    "62": "Systems and Chips, Inc",
    "63": "Bluetooth SIG, Inc",
    "64": "Seiko Epson Corporation",
    "65": "Integrated Silicon Solution Taiwan, Inc.",
    "66": "CONWISE Technology Corporation Ltd",
    "67": "PARROT AUTOMOTIVE SAS",
    "68": "Socket Mobile",
    "69": "Atheros Communications, Inc.",
    "70": "MediaTek, Inc.",
    "71": "Bluegiga",
    "72": "Marvell Technology Group Ltd.",
    "73": "3DSP Corporation",
    "74": "Accel Semiconductor Ltd.",
    "75": "Continental Automotive Systems",
    "76": "Apple, Inc.",
    "77": "Staccato Communications, Inc.",
    "78": "Avago Technologies",
    "79": "APT Ltd.",
    "80": "SiRF Technology, Inc.",
    "81": "Tzero Technologies, Inc.",
    "82": "J&M Corporation",
    "83": "Free2move AB",
    "84": "3DiJoy Corporation",
    "85": "Plantronics, Inc.",
    "86": "Sony Ericsson Mobile Communications",
    "87": "Harman International Industries, Inc.",
    "88": "Vizio, Inc.",
    "89": "Nordic Semiconductor ASA",
    "90": "EM Microelectronic-Marin SA",
    "91": "Ralink Technology Corporation",
    "92": "Belkin International, Inc.",
    "93": "Realtek Semiconductor Corporation",
    "94": "Stonestreet One, LLC",
    "95": "Wicentric, Inc.",
    "96": "RivieraWaves S.A.S",
    "97": "RDA Microelectronics",
    "98": "Gibson Guitars",
    "99": "MiCommand Inc.",
    "100": "Band XI International, LLC",
    "101": "Hewlett-Packard Company",
    "102": "9Solutions Oy",
    "103": "GN Netcom A/S",
    "104": "General Motors",
    "105": "A&D Engineering, Inc.",
    "106": "MindTree Ltd.",
    "107": "Polar Electro OY",
    "108": "Beautiful Enterprise Co., Ltd.",
    "109": "BriarTek, Inc",
    "110": "Summit Data Communications, Inc.",
    "111": "Sound ID",
    "112": "Monster, LLC",
    "113": "connectBlue AB",
    "114": "ShangHai Super Smart Electronics Co. Ltd.",
    "115": "Group Sense Ltd.",
    "116": "Zomm, LLC",
    "117": "Samsung Electronics Co. Ltd.",
    "118": "Creative Technology Ltd.",
    "119": "Laird Technologies",
    "120": "Nike, Inc.",
    "121": "lesswire AG",
    "122": "MStar Semiconductor, Inc.",
    "123": "Hanlynn Technologies",
    "124": "A & R Cambridge",
    "125": "Seers Technology Co., Ltd.",
    "126": "Sports Tracking Technologies Ltd.",
    "127": "Autonet Mobile",
    "128": "DeLorme Publishing Company, Inc.",
    "129": "WuXi Vimicro",
    "130": "Sennheiser Communications A/S",
    "131": "TimeKeeping Systems, Inc.",
    "132": "Ludus Helsinki Ltd.",
    "133": "BlueRadios, Inc.",
    "134": "Equinux AG",
    "135": "Garmin International, Inc.",
    "136": "Ecotest",
    "137": "GN ReSound A/S",
    "138": "Jawbone",
    "139": "Topcon Positioning Systems, LLC",
    "140": "Gimbal Inc. (formerly Qualcomm Labs, Inc. and Qualcomm Retail Solutions, Inc.)",
    "141": "Zscan Software",
    "142": "Quintic Corp",
    "143": "Telit Wireless Solutions GmbH (formerly Stollmann E+V GmbH)",
    "144": "Funai Electric Co., Ltd.",
    "145": "Advanced PANMOBIL systems GmbH & Co. KG",
    "146": "ThinkOptics, Inc.",
    "147": "Universal Electronics, Inc.",
    "148": "Airoha Technology Corp.",
    "149": "NEC Lighting, Ltd.",
    "150": "ODM Technology, Inc.",
    "151": "ConnecteDevice Ltd.",
    "152": "zero1.tv GmbH",
    "153": "i.Tech Dynamic Global Distribution Ltd.",
    "154": "Alpwise",
    "155": "Jiangsu Toppower Automotive Electronics Co., Ltd.",
    "156": "Colorfy, Inc.",
    "157": "Geoforce Inc.",
    "158": "Bose Corporation",
    "159": "Suunto Oy",
    "160": "Kensington Computer Products Group",
    "161": "SR-Medizinelektronik",
    "162": "Vertu Corporation Limited",
    "163": "Meta Watch Ltd.",
    "164": "LINAK A/S",
    "165": "OTL Dynamics LLC",
    "166": "Panda Ocean Inc.",
    "167": "Visteon Corporation",
    "168": "ARP Devices Limited",
    "169": "Magneti Marelli S.p.A",
    "170": "CAEN RFID srl",
    "171": "Ingenieur-Systemgruppe Zahn GmbH",
    "172": "Green Throttle Games",
    "173": "Peter Systemtechnik GmbH",
    "174": "Omegawave Oy",
    "175": "Cinetix",
    "176": "Passif Semiconductor Corp",
    "177": "Saris Cycling Group, Inc",
    "178": "Bekey A/S",
    "179": "Clarinox Technologies Pty. Ltd.",
    "180": "BDE Technology Co., Ltd.",
    "181": "Swirl Networks",
    "182": "Meso international",
    "183": "TreLab Ltd",
    "184": "Qualcomm Innovation Center, Inc. (QuIC)",
    "185": "Johnson Controls, Inc.",
    "186": "Starkey Laboratories Inc.",
    "187": "S-Power Electronics Limited",
    "188": "Ace Sensor Inc",
    "189": "Aplix Corporation",
    "190": "AAMP of America",
    "191": "Stalmart Technology Limited",
    "192": "AMICCOM Electronics Corporation",
    "193": "Shenzhen Excelsecu Data Technology Co.,Ltd",
    "194": "Geneq Inc.",
    "195": "adidas AG",
    "196": "LG Electronics",
    "197": "Onset Computer Corporation",
    "198": "Selfly BV",
    "199": "Quuppa Oy.",
    "200": "GeLo Inc",
    "201": "Evluma",
    "202": "MC10",
    "203": "Binauric SE",
    "204": "Beats Electronics",
    "205": "Microchip Technology Inc.",
    "206": "Elgato Systems GmbH",
    "207": "ARCHOS SA",
    "208": "Dexcom, Inc.",
    "209": "Polar Electro Europe B.V.",
    "210": "Dialog Semiconductor B.V.",
    "211": "Taixingbang Technology (HK) Co,. LTD.",
    "212": "Kawantech",
    "213": "Austco Communication Systems",
    "214": "Timex Group USA, Inc.",
    "215": "Qualcomm Technologies, Inc.",
    "216": "Qualcomm Connected Experiences, Inc.",
    "217": "Voyetra Turtle Beach",
    "218": "txtr GmbH",
    "219": "Biosentronics",
    "220": "Procter & Gamble",
    "221": "Hosiden Corporation",
    "222": "Muzik LLC",
    "223": "Misfit Wearables Corp",
    "224": "Google",
    "225": "Danlers Ltd",
    "226": "Semilink Inc",
    "227": "inMusic Brands, Inc",
    "228": "L.S. Research Inc.",
    "229": "Eden Software Consultants Ltd.",
    "230": "Freshtemp",
    "231": "KS Technologies",
    "232": "ACTS Technologies",
    "233": "Vtrack Systems",
    "234": "Nielsen-Kellerman Company",
    "235": "Server Technology Inc.",
    "236": "BioResearch Associates",
    "237": "Jolly Logic, LLC",
    "238": "Above Average Outcomes, Inc.",
    "239": "Bitsplitters GmbH",
    "240": "PayPal, Inc.",
    "241": "Witron Technology Limited",
    "242": "Morse Project Inc.",
    "243": "Kent Displays Inc.",
    "244": "Nautilus Inc.",
    "245": "Smartifier Oy",
    "246": "Elcometer Limited",
    "247": "VSN Technologies, Inc.",
    "248": "AceUni Corp., Ltd.",
    "249": "StickNFind",
    "250": "Crystal Code AB",
    "251": "KOUKAAM a.s.",
    "252": "Delphi Corporation",
    "253": "ValenceTech Limited",
    "254": "Stanley Black and Decker",
    "255": "Typo Products, LLC",
    "256": "TomTom International BV",
    "257": "Fugoo, Inc.",
    "258": "Keiser Corporation",
    "259": "Bang & Olufsen A/S",
    "260": "PLUS Location Systems Pty Ltd",
    "261": "Ubiquitous Computing Technology Corporation",
    "262": "Innovative Yachtter Solutions",
    "263": "William Demant Holding A/S",
    "264": "Chicony Electronics Co., Ltd.",
    "265": "Atus BV",
    "266": "Codegate Ltd",
    "267": "ERi, Inc",
    "268": "Transducers Direct, LLC",
    "269": "Fujitsu Ten LImited",
    "270": "Audi AG",
    "271": "HiSilicon Technologies Col, Ltd.",
    "272": "Nippon Seiki Co., Ltd.",
    "273": "Steelseries ApS",
    "274": "Visybl Inc.",
    "275": "Openbrain Technologies, Co., Ltd.",
    "276": "Xensr",
    "277": "e.solutions",
    "278": "10AK Technologies",
    "279": "Wimoto Technologies Inc",
    "280": "Radius Networks, Inc.",
    "281": "Wize Technology Co., Ltd.",
    "282": "Qualcomm Labs, Inc.",
    "283": "Hewlett Packard Enterprise",
    "284": "Baidu",
    "285": "Arendi AG",
    "286": "Skoda Auto a.s.",
    "287": "Volkswagen AG",
    "288": "Porsche AG",
    "289": "Sino Wealth Electronic Ltd.",
    "290": "AirTurn, Inc.",
    "291": "Kinsa, Inc",
    "292": "HID Global",
    "293": "SEAT es",
    "294": "Promethean Ltd.",
    "295": "Salutica Allied Solutions",
    "296": "GPSI Group Pty Ltd",
    "297": "Nimble Devices Oy",
    "298": "Changzhou Yongse Infotech Co., Ltd.",
    "299": "SportIQ",
    "300": "TEMEC Instruments B.V.",
    "301": "Sony Corporation",
    "302": "ASSA ABLOY",
    "303": "Clarion Co. Inc.",
    "304": "Warehouse Innovations",
    "305": "Cypress Semiconductor",
    "306": "MADS Inc",
    "307": "Blue Maestro Limited",
    "308": "Resolution Products, Ltd.",
    "309": "Aireware LLC",
    "310": "Silvair, Inc.",
    "311": "Prestigio Plaza Ltd.",
    "312": "NTEO Inc.",
    "313": "Focus Systems Corporation",
    "314": "Tencent Holdings Ltd.",
    "315": "Allegion",
    "316": "Murata Manufacturing Co., Ltd.",
    "317": "WirelessWERX",
    "318": "Nod, Inc.",
    "319": "B&B Manufacturing Company",
    "320": "Alpine Electronics (China) Co., Ltd",
    "321": "FedEx Services",
    "322": "Grape Systems Inc.",
    "323": "Bkon Connect",
    "324": "Lintech GmbH",
    "325": "Novatel Wireless",
    "326": "Ciright",
    "327": "Mighty Cast, Inc.",
    "328": "Ambimat Electronics",
    "329": "Perytons Ltd.",
    "330": "Tivoli Audio, LLC",
    "331": "Master Lock",
    "332": "Mesh-Net Ltd",
    "333": "HUIZHOU DESAY SV AUTOMOTIVE CO., LTD.",
    "334": "Tangerine, Inc.",
    "335": "B&W Group Ltd.",
    "336": "Pioneer Corporation",
    "337": "OnBeep",
    "338": "Vernier Software & Technology",
    "339": "ROL Ergo",
    "340": "Pebble Technology",
    "341": "NETATMO",
    "342": "Accumulate AB",
    "343": "Anhui Huami Information Technology Co., Ltd.",
    "344": "Inmite s.r.o.",
    "345": "ChefSteps, Inc.",
    "346": "micas AG",
    "347": "Biomedical Research Ltd.",
    "348": "Pitius Tec S.L.",
    "349": "Estimote, Inc.",
    "350": "Unikey Technologies, Inc.",
    "351": "Timer Cap Co.",
    "352": "AwoX",
    "353": "yikes",
    "354": "MADSGlobalNZ Ltd.",
    "355": "PCH International",
    "356": "Qingdao Yeelink Information Technology Co., Ltd.",
    "357": "Milwaukee Tool (Formally Milwaukee Electric Tools)",
    "358": "MISHIK Pte Ltd",
    "359": "Ascensia Diabetes Care US Inc.",
    "360": "Spicebox LLC",
    "361": "emberlight",
    "362": "Cooper-Atkins Corporation",
    "363": "Qblinks",
    "364": "MYSPHERA",
    "365": "LifeScan Inc",
    "366": "Volantic AB",
    "367": "Podo Labs, Inc",
    "368": "Roche Diabetes Care AG",
    "369": "Amazon Fulfillment Service",
    "370": "Connovate Technology Private Limited",
    "371": "Kocomojo, LLC",
    "372": "Everykey Inc.",
    "373": "Dynamic Controls",
    "374": "SentriLock",
    "375": "I-SYST inc.",
    "376": "CASIO COMPUTER CO., LTD.",
    "377": "LAPIS Semiconductor Co., Ltd.",
    "378": "Telemonitor, Inc.",
    "379": "taskit GmbH",
    "380": "Daimler AG",
    "381": "BatAndCat",
    "382": "BluDotz Ltd",
    "383": "XTel Wireless ApS",
    "384": "Gigaset Communications GmbH",
    "385": "Gecko Health Innovations, Inc.",
    "386": "HOP Ubiquitous",
    "387": "Walt Disney",
    "388": "Nectar",
    "389": "bel'apps LLC",
    "390": "CORE Lighting Ltd",
    "391": "Seraphim Sense Ltd",
    "392": "Unico RBC",
    "393": "Physical Enterprises Inc.",
    "394": "Able Trend Technology Limited",
    "395": "Konica Minolta, Inc.",
    "396": "Wilo SE",
    "397": "Extron Design Services",
    "398": "Fitbit, Inc.",
    "399": "Fireflies Systems",
    "400": "Intelletto Technologies Inc.",
    "401": "FDK CORPORATION",
    "402": "Cloudleaf, Inc",
    "403": "Maveric Automation LLC",
    "404": "Acoustic Stream Corporation",
    "405": "Zuli",
    "406": "Paxton Access Ltd",
    "407": "WiSilica Inc.",
    "408": "VENGIT Korlatolt Felelossegu Tarsasag",
    "409": "SALTO SYSTEMS S.L.",
    "410": "TRON Forum (formerly T-Engine Forum)",
    "411": "CUBETECH s.r.o.",
    "412": "Cokiya Incorporated",
    "413": "CVS Health",
    "414": "Ceruus",
    "415": "Strainstall Ltd",
    "416": "Channel Enterprises (HK) Ltd.",
    "417": "FIAMM",
    "418": "GIGALANE.CO.,LTD",
    "419": "EROAD",
    "420": "Mine Safety Appliances",
    "421": "Icon Health and Fitness",
    "422": "Asandoo GmbH",
    "423": "ENERGOUS CORPORATION",
    "424": "Taobao",
    "425": "Canon Inc.",
    "426": "Geophysical Technology Inc.",
    "427": "Facebook, Inc.",
    "428": "Trividia Health, Inc.",
    "429": "FlightSafety International",
    "430": "Earlens Corporation",
    "431": "Sunrise Micro Devices, Inc.",
    "432": "Star Micronics Co., Ltd.",
    "433": "Netizens Sp. z o.o.",
    "434": "Nymi Inc.",
    "435": "Nytec, Inc.",
    "436": "Trineo Sp. z o.o.",
    "437": "Nest Labs Inc.",
    "438": "LM Technologies Ltd",
    "439": "General Electric Company",
    "440": "i+D3 S.L.",
    "441": "HANA Micron",
    "442": "Stages Cycling LLC",
    "443": "Cochlear Bone Anchored Solutions AB",
    "444": "SenionLab AB",
    "445": "Syszone Co., Ltd",
    "446": "Pulsate Mobile Ltd.",
    "447": "Hong Kong HunterSun Electronic Limited",
    "448": "pironex GmbH",
    "449": "BRADATECH Corp.",
    "450": "Transenergooil AG",
    "451": "Bunch",
    "452": "DME Microelectronics",
    "453": "Bitcraze AB",
    "454": "HASWARE Inc.",
    "455": "Abiogenix Inc.",
    "456": "Poly-Control ApS",
    "457": "Avi-on",
    "458": "Laerdal Medical AS",
    "459": "Fetch My Pet",
    "460": "Sam Labs Ltd.",
    "461": "Chengdu Synwing Technology Ltd",
    "462": "HOUWA SYSTEM DESIGN, k.k.",
    "463": "BSH",
    "464": "Primus Inter Pares Ltd",
    "465": "August Home, Inc",
    "466": "Gill Electronics",
    "467": "Sky Wave Design",
    "468": "Newlab S.r.l.",
    "469": "ELAD srl",
    "470": "G-wearables inc.",
    "471": "Squadrone Systems Inc.",
    "472": "Code Corporation",
    "473": "Savant Systems LLC",
    "474": "Logitech International SA",
    "475": "Innblue Consulting",
    "476": "iParking Ltd.",
    "477": "Koninklijke Philips Electronics N.V.",
    "478": "Minelab Electronics Pty Limited",
    "479": "Bison Group Ltd.",
    "480": "Widex A/S",
    "481": "Jolla Ltd",
    "482": "Lectronix, Inc.",
    "483": "Caterpillar Inc",
    "484": "Freedom Innovations",
    "485": "Dynamic Devices Ltd",
    "486": "Technology Solutions (UK) Ltd",
    "487": "IPS Group Inc.",
    "488": "STIR",
    "489": "Sano, Inc.",
    "490": "Advanced Application Design, Inc.",
    "491": "AutoMap LLC",
    "492": "Spreadtrum Communications Shanghai Ltd",
    "493": "CuteCircuit LTD",
    "494": "Valeo Service",
    "495": "Fullpower Technologies, Inc.",
    "496": "KloudNation",
    "497": "Zebra Technologies Corporation",
    "498": "Itron, Inc.",
    "499": "The University of Tokyo",
    "500": "UTC Fire and Security",
    "501": "Cool Webthings Limited",
    "502": "DJO Global",
    "503": "Gelliner Limited",
    "504": "Anyka (Guangzhou) Microelectronics Technology Co, LTD",
    "505": "Medtronic Inc.",
    "506": "Gozio Inc.",
    "507": "Form Lifting, LLC",
    "508": "Wahoo Fitness, LLC",
    "509": "Kontakt Micro-Location Sp. z o.o.",
    "510": "Radio Systems Corporation",
    "511": "Freescale Semiconductor, Inc.",
    "512": "Verifone Systems Pte Ltd. Taiwan Branch",
    "513": "AR Timing",
    "514": "Rigado LLC",
    "515": "Kemppi Oy",
    "516": "Tapcentive Inc.",
    "517": "Smartbotics Inc.",
    "518": "Otter Products, LLC",
    "519": "STEMP Inc.",
    "520": "LumiGeek LLC",
    "521": "InvisionHeart Inc.",
    "522": "Macnica Inc.",
    "523": "Jaguar Land Rover Limited",
    "524": "CoroWare Technologies, Inc",
    "525": "Simplo Technology Co., LTD",
    "526": "Omron Healthcare Co., LTD",
    "527": "Comodule GMBH",
    "528": "ikeGPS",
    "529": "Telink Semiconductor Co. Ltd",
    "530": "Interplan Co., Ltd",
    "531": "Wyler AG",
    "532": "IK Multimedia Production srl",
    "533": "Lukoton Experience Oy",
    "534": "MTI Ltd",
    "535": "Tech4home, Lda",
    "536": "Hiotech AB",
    "537": "DOTT Limited",
    "538": "Blue Speck Labs, LLC",
    "539": "Cisco Systems, Inc",
    "540": "Mobicomm Inc",
    "541": "Edamic",
    "542": "Goodnet, Ltd",
    "543": "Luster Leaf Products Inc",
    "544": "Manus Machina BV",
    "545": "Mobiquity Networks Inc",
    "546": "Praxis Dynamics",
    "547": "Philip Morris Products S.A.",
    "548": "Comarch SA",
    "549": "Nestl Nespresso S.A.",
    "550": "Merlinia A/S",
    "551": "LifeBEAM Technologies",
    "552": "Twocanoes Labs, LLC",
    "553": "Muoverti Limited",
    "554": "Stamer Musikanlagen GMBH",
    "555": "Tesla Motors",
    "556": "Pharynks Corporation",
    "557": "Lupine",
    "558": "Siemens AG",
    "559": "Huami (Shanghai) Culture Communication CO., LTD",
    "560": "Foster Electric Company, Ltd",
    "561": "ETA SA",
    "562": "x-Senso Solutions Kft",
    "563": "Shenzhen SuLong Communication Ltd",
    "564": "FengFan (BeiJing) Technology Co, Ltd",
    "565": "Qrio Inc",
    "566": "Pitpatpet Ltd",
    "567": "MSHeli s.r.l.",
    "568": "Trakm8 Ltd",
    "569": "JIN CO, Ltd",
    "570": "Alatech Tehnology",
    "571": "Beijing CarePulse Electronic Technology Co, Ltd",
    "572": "Awarepoint",
    "573": "ViCentra B.V.",
    "574": "Raven Industries",
    "575": "WaveWare Technologies Inc.",
    "576": "Argenox Technologies",
    "577": "Bragi GmbH",
    "578": "16Lab Inc",
    "579": "Masimo Corp",
    "580": "Iotera Inc",
    "581": "Endress+Hauser",
    "582": "ACKme Networks, Inc.",
    "583": "FiftyThree Inc.",
    "584": "Parker Hannifin Corp",
    "585": "Transcranial Ltd",
    "586": "Uwatec AG",
    "587": "Orlan LLC",
    "588": "Blue Clover Devices",
    "589": "M-Way Solutions GmbH",
    "590": "Microtronics Engineering GmbH",
    "591": "Schneider Schreibgerte GmbH",
    "592": "Sapphire Circuits LLC",
    "593": "Lumo Bodytech Inc.",
    "594": "UKC Technosolution",
    "595": "Xicato Inc.",
    "596": "Playbrush",
    "597": "Dai Nippon Printing Co., Ltd.",
    "598": "G24 Power Limited",
    "599": "AdBabble Local Commerce Inc.",
    "600": "Devialet SA",
    "601": "ALTYOR",
    "602": "University of Applied Sciences Valais/Haute Ecole Valaisanne",
    "603": "Five Interactive, LLC dba Zendo",
    "604": "NetEaseHangzhouNetwork co.Ltd.",
    "605": "Lexmark International Inc.",
    "606": "Fluke Corporation",
    "607": "Yardarm Technologies",
    "608": "SensaRx",
    "609": "SECVRE GmbH",
    "610": "Glacial Ridge Technologies",
    "611": "Identiv, Inc.",
    "612": "DDS, Inc.",
    "613": "SMK Corporation",
    "614": "Schawbel Technologies LLC",
    "615": "XMI Systems SA",
    "616": "Cerevo",
    "617": "Torrox GmbH & Co KG",
    "618": "Gemalto",
    "619": "DEKA Research & Development Corp.",
    "620": "Domster Tadeusz Szydlowski",
    "621": "Technogym SPA",
    "622": "FLEURBAEY BVBA",
    "623": "Aptcode Solutions",
    "624": "LSI ADL Technology",
    "625": "Animas Corp",
    "626": "Alps Electric Co., Ltd.",
    "627": "OCEASOFT",
    "628": "Motsai Research",
    "629": "Geotab",
    "630": "E.G.O. Elektro-Gertebau GmbH",
    "631": "bewhere inc",
    "632": "Johnson Outdoors Inc",
    "633": "steute Schaltgerate GmbH & Co. KG",
    "634": "Ekomini inc.",
    "635": "DEFA AS",
    "636": "Aseptika Ltd",
    "637": "HUAWEI Technologies Co., Ltd. ( )",
    "638": "HabitAware, LLC",
    "639": "ruwido austria gmbh",
    "640": "ITEC corporation",
    "641": "StoneL",
    "642": "Sonova AG",
    "643": "Maven Machines, Inc.",
    "644": "Synapse Electronics",
    "645": "Standard Innovation Inc.",
    "646": "RF Code, Inc.",
    "647": "Wally Ventures S.L.",
    "648": "Willowbank Electronics Ltd",
    "649": "SK Telecom",
    "650": "Jetro AS",
    "651": "Code Gears LTD",
    "652": "NANOLINK APS",
    "653": "IF, LLC",
    "654": "RF Digital Corp",
    "655": "Church & Dwight Co., Inc",
    "656": "Multibit Oy",
    "657": "CliniCloud Inc",
    "658": "SwiftSensors",
    "659": "Blue Bite",
    "660": "ELIAS GmbH",
    "661": "Sivantos GmbH",
    "662": "Petzl",
    "663": "storm power ltd",
    "664": "EISST Ltd",
    "665": "Inexess Technology Simma KG",
    "666": "Currant, Inc.",
    "667": "C2 Development, Inc.",
    "668": "Blue Sky Scientific, LLC",
    "669": "ALOTTAZS LABS, LLC",
    "670": "Kupson spol. s r.o.",
    "671": "Areus Engineering GmbH",
    "672": "Impossible Camera GmbH",
    "673": "InventureTrack Systems",
    "674": "LockedUp",
    "675": "Itude",
    "676": "Pacific Lock Company",
    "677": "Tendyron Corporation ( )",
    "678": "Robert Bosch GmbH",
    "679": "Illuxtron international B.V.",
    "680": "miSport Ltd.",
    "681": "Chargelib",
    "682": "Doppler Lab",
    "683": "BBPOS Limited",
    "684": "RTB Elektronik GmbH & Co. KG",
    "685": "Rx Networks, Inc.",
    "686": "WeatherFlow, Inc.",
    "687": "Technicolor USA Inc.",
    "688": "Bestechnic(Shanghai),Ltd",
    "689": "Raden Inc",
    "690": "JouZen Oy",
    "691": "CLABER S.P.A.",
    "692": "Hyginex, Inc.",
    "693": "HANSHIN ELECTRIC RAILWAY CO.,LTD.",
    "694": "Schneider Electric",
    "695": "Oort Technologies LLC",
    "696": "Chrono Therapeutics",
    "697": "Rinnai Corporation",
    "698": "Swissprime Technologies AG",
    "699": "Koha.,Co.Ltd",
    "700": "Genevac Ltd",
    "701": "Chemtronics",
    "702": "Seguro Technology Sp. z o.o.",
    "703": "Redbird Flight Simulations",
    "704": "Dash Robotics",
    "705": "LINE Corporation",
    "706": "Guillemot Corporation",
    "707": "Techtronic Power Tools Technology Limited",
    "708": "Wilson Sporting Goods",
    "709": "Lenovo (Singapore) Pte Ltd. ( )",
    "710": "Ayatan Sensors",
    "711": "Electronics Tomorrow Limited",
    "712": "VASCO Data Security International, Inc.",
    "713": "PayRange Inc.",
    "714": "ABOV Semiconductor",
    "715": "AINA-Wireless Inc.",
    "716": "Eijkelkamp Soil & Water",
    "717": "BMA ergonomics b.v.",
    "718": "Teva Branded Pharmaceutical Products R&D, Inc.",
    "719": "Anima",
    "720": "3M",
    "721": "Empatica Srl",
    "722": "Afero, Inc.",
    "723": "Powercast Corporation",
    "724": "Secuyou ApS",
    "725": "OMRON Corporation",
    "726": "Send Solutions",
    "727": "NIPPON SYSTEMWARE CO.,LTD.",
    "728": "Neosfar",
    "729": "Fliegl Agrartechnik GmbH",
    "730": "Gilvader",
    "731": "Digi International Inc (R)",
    "732": "DeWalch Technologies, Inc.",
    "733": "Flint Rehabilitation Devices, LLC",
    "734": "Samsung SDS Co., Ltd.",
    "735": "Blur Product Development",
    "736": "University of Michigan",
    "737": "Victron Energy BV",
    "738": "NTT docomo",
    "739": "Carmanah Technologies Corp.",
    "740": "Bytestorm Ltd.",
    "741": "Espressif Incorporated ( () )",
    "742": "Unwire",
    "743": "Connected Yard, Inc.",
    "744": "American Music Environments",
    "745": "Sensogram Technologies, Inc.",
    "746": "Fujitsu Limited",
    "747": "Ardic Technology",
    "748": "Delta Systems, Inc",
    "749": "HTC Corporation",
    "750": "Citizen Holdings Co., Ltd.",
    "751": "SMART-INNOVATION.inc",
    "752": "Blackrat Software",
    "753": "The Idea Cave, LLC",
    "754": "GoPro, Inc.",
    "755": "AuthAir, Inc",
    "756": "Vensi, Inc.",
    "757": "Indagem Tech LLC",
    "758": "Intemo Technologies",
    "759": "DreamVisions co., Ltd.",
    "760": "Runteq Oy Ltd",
    "761": "IMAGINATION TECHNOLOGIES LTD",
    "762": "CoSTAR TEchnologies",
    "763": "Clarius Mobile Health Corp.",
    "764": "Shanghai Frequen Microelectronics Co., Ltd.",
    "765": "Uwanna, Inc.",
    "766": "Lierda Science & Technology Group Co., Ltd.",
    "767": "Silicon Laboratories",
    "768": "World Moto Inc.",
    "769": "Giatec Scientific Inc.",
    "770": "Loop Devices, Inc",
    "771": "IACA electronique",
    "772": "Proxy Technologies, Inc.",
    "773": "Swipp ApS",
    "774": "Life Laboratory Inc.",
    "775": "FUJI INDUSTRIAL CO.,LTD.",
    "776": "Surefire, LLC",
    "777": "Dolby Labs",
    "778": "Ellisys",
    "779": "Magnitude Lighting Converters",
    "780": "Hilti AG",
    "781": "Devdata S.r.l.",
    "782": "Deviceworx",
    "783": "Shortcut Labs",
    "784": "SGL Italia S.r.l.",
    "785": "PEEQ DATA",
    "786": "Ducere Technologies Pvt Ltd",
    "787": "DiveNav, Inc.",
    "788": "RIIG AI Sp. z o.o.",
    "789": "Thermo Fisher Scientific",
    "790": "AG Measurematics Pvt. Ltd.",
    "791": "CHUO Electronics CO., LTD.",
    "792": "Aspenta International",
    "793": "Eugster Frismag AG",
    "794": "Amber wireless GmbH",
    "795": "HQ Inc",
    "796": "Lab Sensor Solutions",
    "797": "Enterlab ApS",
    "798": "Eyefi, Inc.",
    "799": "MetaSystem S.p.A.",
    "800": "SONO ELECTRONICS. CO., LTD",
    "801": "Jewelbots",
    "802": "Compumedics Limited",
    "803": "Rotor Bike Components",
    "804": "Astro, Inc.",
    "805": "Amotus Solutions",
    "806": "Healthwear Technologies (Changzhou)Ltd",
    "807": "Essex Electronics",
    "808": "Grundfos A/S",
    "809": "Eargo, Inc.",
    "810": "Electronic Design Lab",
    "811": "ESYLUX",
    "812": "NIPPON SMT.CO.,Ltd",
    "813": "BM innovations GmbH",
    "814": "indoormap",
    "815": "OttoQ Inc",
    "816": "North Pole Engineering",
    "817": "3flares Technologies Inc.",
    "818": "Electrocompaniet A.S.",
    "819": "Mul-T-Lock",
    "820": "Corentium AS",
    "821": "Enlighted Inc",
    "822": "GISTIC",
    "823": "AJP2 Holdings, LLC",
    "824": "COBI GmbH",
    "825": "Blue Sky Scientific, LLC",
    "826": "Appception, Inc.",
    "827": "Courtney Thorne Limited",
    "828": "Virtuosys",
    "829": "TPV Technology Limited",
    "830": "Monitra SA",
    "831": "Automation Components, Inc.",
    "832": "Letsense s.r.l.",
    "833": "Etesian Technologies LLC",
    "834": "GERTEC BRASIL LTDA.",
    "835": "Drekker Development Pty. Ltd.",
    "836": "Whirl Inc",
    "837": "Locus Positioning",
    "838": "Acuity Brands Lighting, Inc",
    "839": "Prevent Biometrics",
    "840": "Arioneo",
    "841": "VersaMe",
    "842": "Vaddio",
    "843": "Libratone A/S",
    "844": "HM Electronics, Inc.",
    "845": "TASER International, Inc.",
    "846": "SafeTrust Inc.",
    "847": "Heartland Payment Systems",
    "848": "Bitstrata Systems Inc.",
    "849": "Pieps GmbH",
    "850": "iRiding(Xiamen)Technology Co.,Ltd.",
    "851": "Alpha Audiotronics, Inc.",
    "852": "TOPPAN FORMS CO.,LTD.",
    "853": "Sigma Designs, Inc.",
    "854": "Spectrum Brands, Inc.",
    "855": "Polymap Wireless",
    "856": "MagniWare Ltd.",
    "857": "Novotec Medical GmbH",
    "858": "Medicom Innovation Partner a/s",
    "859": "Matrix Inc.",
    "860": "Eaton Corporation",
    "861": "KYS",
    "862": "Naya Health, Inc.",
    "863": "Acromag",
    "864": "Insulet Corporation",
    "865": "Wellinks Inc.",
    "866": "ON Semiconductor",
    "867": "FREELAP SA",
    "868": "Favero Electronics Srl",
    "869": "BioMech Sensor LLC",
    "870": "BOLTT Sports technologies Private limited",
    "871": "Saphe International",
    "872": "Metormote AB",
    "873": "littleBits",
    "874": "SetPoint Medical",
    "875": "BRControls Products BV",
    "876": "Zipcar",
    "877": "AirBolt Pty Ltd",
    "878": "KeepTruckin Inc",
    "879": "Motiv, Inc.",
    "880": "Wazombi Labs O",
    "881": "ORBCOMM",
    "882": "Nixie Labs, Inc.",
    "883": "AppNearMe Ltd",
    "884": "Holman Industries",
    "885": "Expain AS",
    "886": "Electronic Temperature Instruments Ltd",
    "887": "Plejd AB",
    "888": "Propeller Health",
    "889": "Shenzhen iMCO Electronic Technology Co.,Ltd",
    "890": "Algoria",
    "891": "Apption Labs Inc.",
    "892": "Cronologics Corporation",
    "893": "MICRODIA Ltd.",
    "894": "lulabytes S.L.",
    "895": "Nestec S.A.",
    "896": "LLC \"MEGA-F service\"",
    "897": "Sharp Corporation",
    "898": "Precision Outcomes Ltd",
    "899": "Kronos Incorporated",
    "900": "OCOSMOS Co., Ltd.",
    "901": "Embedded Electronic Solutions Ltd. dba e2Solutions",
    "902": "Aterica Inc.",
    "903": "BluStor PMC, Inc.",
    "904": "Kapsch TrafficCom AB",
    "905": "ActiveBlu Corporation",
    "906": "Kohler Mira Limited",
    "907": "Noke",
    "908": "Appion Inc.",
    "909": "Resmed Ltd",
    "910": "Crownstone B.V.",
    "911": "Xiaomi Inc.",
    "912": "INFOTECH s.r.o.",
    "913": "Thingsquare AB",
    "914": "T&D",
    "915": "LAVAZZA S.p.A.",
    "916": "Netclearance Systems, Inc.",
    "917": "SDATAWAY",
    "918": "BLOKS GmbH",
    "919": "LEGO System A/S",
    "920": "Thetatronics Ltd",
    "921": "Nikon Corporation",
    "922": "NeST",
    "923": "South Silicon Valley Microelectronics",
    "924": "ALE International",
    "925": "CareView Communications, Inc.",
    "926": "SchoolBoard Limited",
    "927": "Molex Corporation",
    "928": "IVT Wireless Limited",
    "929": "Alpine Labs LLC",
    "930": "Candura Instruments",
    "931": "SmartMovt Technology Co., Ltd",
    "932": "Token Zero Ltd",
    "933": "ACE CAD Enterprise Co., Ltd. (ACECAD)",
    "934": "Medela, Inc",
    "935": "AeroScout",
    "936": "Esrille Inc.",
    "937": "THINKERLY SRL",
    "938": "Exon Sp. z o.o.",
    "939": "Meizu Technology Co., Ltd.",
    "940": "Smablo LTD",
    "941": "XiQ",
    "942": "Allswell Inc.",
    "943": "Comm-N-Sense Corp DBA Verigo",
    "944": "VIBRADORM GmbH",
    "945": "Otodata Wireless Network Inc.",
    "946": "Propagation Systems Limited",
    "947": "Midwest Instruments & Controls",
    "948": "Alpha Nodus, inc.",
    "949": "petPOMM, Inc",
    "950": "Mattel",
    "951": "Airbly Inc.",
    "952": "A-Safe Limited",
    "953": "FREDERIQUE CONSTANT SA",
    "954": "Maxscend Microelectronics Company Limited",
    "955": "Abbott Diabetes Care",
    "956": "ASB Bank Ltd",
    "957": "amadas",
    "958": "Applied Science, Inc.",
    "959": "iLumi Solutions Inc.",
    "960": "Arch Systems Inc.",
    "961": "Ember Technologies, Inc.",
    "962": "Snapchat Inc",
    "963": "Casambi Technologies Oy",
    "964": "Pico Technology Inc.",
    "965": "St. Jude Medical, Inc.",
    "966": "Intricon",
    "967": "Structural Health Systems, Inc.",
    "968": "Avvel International",
    "969": "Gallagher Group",
    "970": "In2things Automation Pvt. Ltd.",
    "971": "SYSDEV Srl",
    "972": "Vonkil Technologies Ltd",
    "973": "Wynd Technologies, Inc.",
    "974": "CONTRINEX S.A.",
    "975": "MIRA, Inc.",
    "976": "Watteam Ltd",
    "977": "Density Inc.",
    "978": "IOT Pot India Private Limited",
    "979": "Sigma Connectivity AB",
    "980": "PEG PEREGO SPA",
    "981": "Wyzelink Systems Inc.",
    "982": "Yota Devices LTD",
    "983": "FINSECUR",
    "984": "Zen-Me Labs Ltd",
    "985": "3IWare Co., Ltd.",
    "986": "EnOcean GmbH",
    "987": "Instabeat, Inc",
    "988": "Nima Labs",
    "989": "Andreas Stihl AG & Co. KG",
    "990": "Nathan Rhoades LLC",
    "991": "Grob Technologies, LLC",
    "992": "Actions (Zhuhai) Technology Co., Limited",
    "993": "SPD Development Company Ltd",
    "994": "Sensoan Oy",
    "995": "Qualcomm Life Inc",
    "996": "Chip-ing AG",
    "997": "ffly4u",
    "998": "IoT Instruments Oy",
    "999": "TRUE Fitness Technology",
    "1000": "Reiner Kartengeraete GmbH & Co. KG.",
    "1001": "SHENZHEN LEMONJOY TECHNOLOGY CO., LTD.",
    "1002": "Hello Inc.",
    "1003": "Evollve Inc.",
    "1004": "Jigowatts Inc.",
    "1005": "BASIC MICRO.COM,INC.",
    "1006": "CUBE TECHNOLOGIES",
    "1007": "foolography GmbH",
    "1008": "CLINK",
    "1009": "Hestan Smart Cooking Inc.",
    "1010": "WindowMaster A/S",
    "1011": "Flowscape AB",
    "1012": "PAL Technologies Ltd",
    "1013": "WHERE, Inc.",
    "1014": "Iton Technology Corp.",
    "1015": "Owl Labs Inc.",
    "1016": "Rockford Corp.",
    "1017": "Becon Technologies Co.,Ltd.",
    "1018": "Vyassoft Technologies Inc",
    "1019": "Nox Medical",
    "1020": "Kimberly-Clark",
    "1021": "Trimble Navigation Ltd.",
    "1022": "Littelfuse",
    "1023": "Withings",
    "1024": "i-developer IT Beratung UG",
    "1025": "",
    "1026": "Sears Holdings Corporation",
    "1027": "Gantner Electronic GmbH",
    "1028": "Authomate Inc",
    "1029": "Vertex International, Inc.",
    "1030": "Airtago",
    "1031": "Swiss Audio SA",
    "1032": "ToGetHome Inc.",
    "1033": "AXIS",
    "1034": "Openmatics",
    "1035": "Jana Care Inc.",
    "1036": "Senix Corporation",
    "1037": "NorthStar Battery Company, LLC",
    "1038": "SKF (U.K.) Limited",
    "1039": "CO-AX Technology, Inc.",
    "1040": "Fender Musical Instruments",
    "1041": "Luidia Inc",
    "1042": "SEFAM",
    "1043": "Wireless Cables Inc",
    "1044": "Lightning Protection International Pty Ltd",
    "1045": "Uber Technologies Inc",
    "1046": "SODA GmbH",
    "1047": "Fatigue Science",
    "1048": "Alpine Electronics Inc.",
    "1049": "Novalogy LTD",
    "1050": "Friday Labs Limited",
    "1051": "OrthoAccel Technologies",
    "1052": "WaterGuru, Inc.",
    "1053": "Benning Elektrotechnik und Elektronik GmbH & Co. KG",
    "1054": "Dell Computer Corporation",
    "1055": "Kopin Corporation",
    "1056": "TecBakery GmbH",
    "1057": "Backbone Labs, Inc.",
    "1058": "DELSEY SA",
    "1059": "Chargifi Limited",
    "1060": "Trainesense Ltd.",
    "1061": "Unify Software and Solutions GmbH & Co. KG",
    "1062": "Husqvarna AB",
    "1063": "Focus fleet and fuel management inc",
    "1064": "SmallLoop, LLC",
    "1065": "Prolon Inc.",
    "1066": "BD Medical",
    "1067": "iMicroMed Incorporated",
    "1068": "Ticto N.V.",
    "1069": "Meshtech AS",
    "1070": "MemCachier Inc.",
    "1071": "Danfoss A/S",
    "1072": "SnapStyk Inc.",
    "1073": "Amway Corporation",
    "1074": "Silk Labs, Inc.",
    "1075": "Pillsy Inc.",
    "1076": "Hatch Baby, Inc.",
    "1077": "Blocks Wearables Ltd.",
    "1078": "Drayson Technologies (Europe) Limited",
    "1079": "eBest IOT Inc.",
    "1080": "Helvar Ltd",
    "1081": "Radiance Technologies",
    "1082": "Nuheara Limited",
    "1083": "Appside co., ltd.",
    "1084": "DeLaval",
    "1085": "Coiler Corporation",
    "1086": "Thermomedics, Inc.",
    "1087": "Tentacle Sync GmbH",
    "1088": "Valencell, Inc.",
    "1089": "iProtoXi Oy",
    "1090": "SECOM CO., LTD.",
    "1091": "Tucker International LLC",
    "1092": "Metanate Limited",
    "1093": "Kobian Canada Inc.",
    "1094": "NETGEAR, Inc.",
    "1095": "Fabtronics Australia Pty Ltd",
    "1096": "Grand Centrix GmbH",
    "1097": "1UP USA.com llc",
    "1098": "SHIMANO INC.",
    "1099": "Nain Inc.",
    "1100": "LifeStyle Lock, LLC",
    "1101": "VEGA Grieshaber KG",
    "1102": "Xtrava Inc.",
    "1103": "TTS Tooltechnic Systems AG & Co. KG",
    "1104": "Teenage Engineering AB",
    "1105": "Tunstall Nordic AB",
    "1106": "Svep Design Center AB",
    "1107": "GreenPeak Technologies BV",
    "1108": "Sphinx Electronics GmbH & Co KG",
    "1109": "Atomation",
    "1110": "Nemik Consulting Inc",
    "1111": "RF INNOVATION",
    "1112": "Mini Solution Co., Ltd.",
    "1113": "Lumenetix, Inc",
    "1114": "2048450 Ontario Inc",
    "1115": "SPACEEK LTD",
    "1116": "Delta T Corporation",
    "1117": "Boston Scientific Corporation",
    "1118": "Nuviz, Inc.",
    "1119": "Real Time Automation, Inc.",
    "1120": "Kolibree",
    "1121": "vhf elektronik GmbH",
    "1122": "Bonsai Systems GmbH",
    "1123": "Fathom Systems Inc.",
    "1124": "Bellman & Symfon",
    "1125": "International Forte Group LLC",
    "1126": "CycleLabs Solutions inc.",
    "1127": "Codenex Oy",
    "1128": "Kynesim Ltd",
    "1129": "Palago AB",
    "1130": "INSIGMA INC.",
    "1131": "PMD Solutions",
    "1132": "Qingdao Realtime Technology Co., Ltd.",
    "1133": "BEGA Gantenbrink-Leuchten KG",
    "1134": "Pambor Ltd.",
    "1135": "Develco Products A/S",
    "1136": "iDesign s.r.l.",
    "1137": "TiVo Corp",
    "1138": "Control-J Pty Ltd",
    "1139": "Steelcase, Inc.",
    "1140": "iApartment co., ltd.",
    "1141": "Icom inc.",
    "1142": "Oxstren Wearable Technologies Private Limited",
    "1143": "Blue Spark Technologies",
    "1144": "FarSite Communications Limited",
    "1145": "mywerk system GmbH",
    "1146": "Sinosun Technology Co., Ltd.",
    "1147": "MIYOSHI ELECTRONICS CORPORATION",
    "1148": "POWERMAT LTD",
    "1149": "Occly LLC",
    "1150": "OurHub Dev IvS",
    "1151": "Pro-Mark, Inc.",
    "1152": "Dynometrics Inc.",
    "1153": "Quintrax Limited",
    "1154": "POS Tuning Udo Vosshenrich GmbH & Co. KG",
    "1155": "Multi Care Systems B.V.",
    "1156": "Revol Technologies Inc",
    "1157": "SKIDATA AG",
    "1158": "DEV TECNOLOGIA INDUSTRIA, COMERCIO E MANUTENCAO DE EQUIPAMENTOS LTDA. - ME",
    "1159": "Centrica Connected Home",
    "1160": "Automotive Data Solutions Inc",
    "1161": "Igarashi Engineering",
    "1162": "Taelek Oy",
    "1163": "CP Electronics Limited",
    "1164": "Vectronix AG",
    "1165": "S-Labs Sp. z o.o.",
    "1166": "Companion Medical, Inc.",
    "1167": "BlueKitchen GmbH",
    "1168": "Matting AB",
    "1169": "SOREX - Wireless Solutions GmbH",
    "1170": "ADC Technology, Inc.",
    "1171": "Lynxemi Pte Ltd",
    "1172": "SENNHEISER electronic GmbH & Co. KG",
    "1173": "LMT Mercer Group, Inc",
    "1174": "Polymorphic Labs LLC",
    "1175": "Cochlear Limited",
    "1176": "METER Group, Inc. USA",
    "1177": "Ruuvi Innovations Ltd.",
    "1178": "Situne AS",
    "1179": "nVisti, LLC",
    "1180": "DyOcean",
    "1181": "Uhlmann & Zacher GmbH",
    "1182": "AND!XOR LLC",
    "1183": "tictote AB",
    "1184": "Vypin, LLC",
    "1185": "PNI Sensor Corporation",
    "1186": "ovrEngineered, LLC",
    "1187": "GT-tronics HK Ltd",
    "1188": "Herbert Waldmann GmbH & Co. KG",
    "1189": "Guangzhou FiiO Electronics Technology Co.,Ltd",
    "1190": "Vinetech Co., Ltd",
    "1191": "Dallas Logic Corporation",
    "1192": "BioTex, Inc.",
    "1193": "DISCOVERY SOUND TECHNOLOGY, LLC",
    "1194": "LINKIO SAS",
    "1195": "Harbortronics, Inc.",
    "1196": "Undagrid B.V.",
    "1197": "Shure Inc",
    "1198": "ERM Electronic Systems LTD",
    "1199": "BIOROWER Handelsagentur GmbH",
    "1200": "Weba Sport und Med. Artikel GmbH",
    "1201": "Kartographers Technologies Pvt. Ltd.",
    "1202": "The Shadow on the Moon",
    "1203": "mobike (Hong Kong) Limited",
    "1204": "Inuheat Group AB",
    "1205": "Swiftronix AB",
    "1206": "Diagnoptics Technologies",
    "1207": "Analog Devices, Inc.",
    "1208": "Soraa Inc.",
    "1209": "CSR Building Products Limited",
    "1210": "Crestron Electronics, Inc.",
    "1211": "Neatebox Ltd",
    "1212": "Draegerwerk AG & Co. KGaA",
    "1213": "AlbynMedical",
    "1214": "Averos FZCO",
    "1215": "VIT Initiative, LLC",
    "1216": "Statsports International",
    "1217": "Sospitas, s.r.o.",
    "1218": "Dmet Products Corp.",
    "1219": "Mantracourt Electronics Limited",
    "1220": "TeAM Hutchins AB",
    "1221": "Seibert Williams Glass, LLC",
    "1222": "Insta GmbH",
    "1223": "Svantek Sp. z o.o.",
    "1224": "Shanghai Flyco Electrical Appliance Co., Ltd.",
    "1225": "Thornwave Labs Inc",
    "1226": "Steiner-Optik GmbH",
    "1227": "Novo Nordisk A/S",
    "1228": "Enflux Inc.",
    "1229": "Safetech Products LLC",
    "1230": "GOOOLED S.R.L.",
    "1231": "DOM Sicherheitstechnik GmbH & Co. KG",
    "1232": "Olympus Corporation",
    "1233": "KTS GmbH",
    "1234": "Anloq Technologies Inc.",
    "1235": "Queercon, Inc",
    "1236": "5th Element Ltd",
    "1237": "Gooee Limited",
    "1238": "LUGLOC LLC",
    "1239": "Blincam, Inc.",
    "1240": "FUJIFILM Corporation",
    "1241": "RandMcNally",
    "1242": "Franceschi Marina snc",
    "1243": "Engineered Audio, LLC.",
    "1244": "IOTTIVE (OPC) PRIVATE LIMITED",
    "1245": "4MOD Technology",
    "1246": "Lutron Electronics Co., Inc.",
    "1247": "Emerson",
    "1248": "Guardtec, Inc.",
    "1249": "REACTEC LIMITED",
    "1250": "EllieGrid",
    "1251": "Under Armour",
    "1252": "Woodenshark",
    "1253": "Avack Oy",
    "1254": "Smart Solution Technology, Inc.",
    "1255": "REHABTRONICS INC.",
    "1256": "STABILO International",
    "1257": "Busch Jaeger Elektro GmbH",
    "1258": "Pacific Bioscience Laboratories, Inc",
    "1259": "Bird Home Automation GmbH",
    "1260": "Motorola Solutions",
    "1261": "R9 Technology, Inc.",
    "1262": "Auxivia",
    "1263": "DaisyWorks, Inc",
    "1264": "Kosi Limited",
    "1265": "Theben AG",
    "1266": "InDreamer Techsol Private Limited",
    "1267": "Cerevast Medical",
    "1268": "ZanCompute Inc.",
    "1269": "Pirelli Tyre S.P.A.",
    "1270": "McLear Limited",
    "1271": "Shenzhen Huiding Technology Co.,Ltd.",
    "1272": "Convergence Systems Limited",
    "1273": "Interactio",
    "1274": "Androtec GmbH",
    "1275": "Benchmark Drives GmbH & Co. KG",
    "1276": "SwingLync L. L. C.",
    "1277": "Tapkey GmbH",
    "1278": "Woosim Systems Inc.",
    "1279": "Microsemi Corporation",
    "1280": "Wiliot LTD.",
    "1281": "Polaris IND",
    "1282": "Specifi-Kali LLC",
    "1283": "Locoroll, Inc",
    "1284": "PHYPLUS Inc",
    "1285": "Inplay Technologies LLC",
    "1286": "Hager",
    "1287": "Yellowcog",
    "1288": "Axes System sp. z o. o.",
    "1289": "myLIFTER Inc.",
    "1290": "Shake-on B.V.",
    "1291": "Vibrissa Inc.",
    "1292": "OSRAM GmbH",
    "1293": "TRSystems GmbH",
    "1294": "Yichip Microelectronics (Hangzhou) Co.,Ltd.",
    "1295": "Foundation Engineering LLC",
    "1296": "UNI-ELECTRONICS, INC.",
    "1297": "Brookfield Equinox LLC",
    "1298": "Soprod SA",
    "1299": "9974091 Canada Inc.",
    "1300": "FIBRO GmbH",
    "1301": "RB Controls Co., Ltd.",
    "1302": "Footmarks",
    "1303": "Amcore AB",
    "1304": "MAMORIO.inc",
    "1305": "Tyto Life LLC",
    "1306": "Leica Camera AG",
    "1307": "Angee Technologies Ltd.",
    "1308": "EDPS",
    "1309": "OFF Line Co., Ltd.",
    "1310": "Detect Blue Limited",
    "1311": "Setec Pty Ltd",
    "1312": "Target Corporation",
    "1313": "IAI Corporation",
    "1314": "NS Tech, Inc.",
    "1315": "MTG Co., Ltd.",
    "1316": "Hangzhou iMagic Technology Co., Ltd",
    "1317": "HONGKONG NANO IC TECHNOLOGIES CO., LIMITED",
    "1318": "Honeywell International Inc.",
    "1319": "Albrecht JUNG",
    "1320": "Lunera Lighting Inc.",
    "1321": "Lumen UAB",
    "1322": "Keynes Controls Ltd",
    "1323": "Novartis AG",
    "1324": "Geosatis SA",
    "1325": "EXFO, Inc.",
    "1326": "LEDVANCE GmbH",
    "1327": "Center ID Corp.",
    "1328": "Adolene, Inc.",
    "1329": "D&M Holdings Inc.",
    "1330": "CRESCO Wireless, Inc.",
    "1331": "Nura Operations Pty Ltd",
    "1332": "Frontiergadget, Inc.",
    "1333": "Smart Component Technologies Limited",
    "1334": "ZTR Control Systems LLC",
    "1335": "MetaLogics Corporation",
    "1336": "Medela AG",
    "1337": "OPPLE Lighting Co., Ltd",
    "1338": "Savitech Corp.,",
    "1339": "prodigy",
    "1340": "Screenovate Technologies Ltd",
    "1341": "TESA SA",
    "1342": "CLIM8 LIMITED",
    "1343": "Silergy Corp",
    "1344": "SilverPlus, Inc",
    "1345": "Sharknet srl",
    "1346": "Mist Systems, Inc.",
    "1347": "MIWA LOCK CO.,Ltd",
    "1348": "OrthoSensor, Inc.",
    "1349": "Candy Hoover Group s.r.l",
    "1350": "Apexar Technologies S.A.",
    "1351": "LOGICDATA d.o.o.",
    "1352": "Knick Elektronische Messgeraete GmbH & Co. KG",
    "1353": "Smart Technologies and Investment Limited",
    "1354": "Linough Inc.",
    "1355": "Advanced Electronic Designs, Inc.",
    "1356": "Carefree Scott Fetzer Co Inc",
    "1357": "Sensome",
    "1358": "FORTRONIK storitve d.o.o.",
    "1359": "Sinnoz",
    "1360": "Versa Networks, Inc.",
    "1361": "Sylero",
    "1362": "Avempace SARL",
    "1363": "Nintendo Co., Ltd.",
    "1364": "National Instruments",
    "1365": "KROHNE Messtechnik GmbH",
    "1366": "Otodynamics Ltd",
    "1367": "Arwin Technology Limited",
    "1368": "benegear, inc.",
    "1369": "Newcon Optik",
    "1370": "CANDY HOUSE, Inc.",
    "1371": "FRANKLIN TECHNOLOGY INC",
    "1372": "Lely",
    "1373": "Valve Corporation",
    "1374": "Hekatron Vertriebs GmbH",
    "1375": "PROTECH S.A.S. DI GIRARDI ANDREA & C.",
    "1376": "Sarita CareTech IVS",
    "1377": "Finder S.p.A.",
    "1378": "Thalmic Labs Inc.",
    "1379": "Steinel Vertrieb GmbH",
    "1380": "Beghelli Spa",
    "1381": "Beijing Smartspace Technologies Inc.",
    "1382": "CORE TRANSPORT TECHNOLOGIES NZ LIMITED",
    "1383": "Xiamen Everesports Goods Co., Ltd",
    "1384": "Bodyport Inc.",
    "1385": "Audionics System, INC.",
    "1386": "Flipnavi Co.,Ltd.",
    "1387": "Rion Co., Ltd.",
    "1388": "Long Range Systems, LLC",
    "1389": "Redmond Industrial Group LLC",
    "1390": "VIZPIN INC.",
    "1391": "BikeFinder AS",
    "1392": "Consumer Sleep Solutions LLC",
    "1393": "PSIKICK, INC.",
    "1394": "AntTail.com",
    "1395": "Lighting Science Group Corp.",
    "1396": "AFFORDABLE ELECTRONICS INC",
    "1397": "Integral Memroy Plc",
    "1398": "Globalstar, Inc.",
    "1399": "True Wearables, Inc.",
    "1400": "Wellington Drive Technologies Ltd",
    "1401": "Ensemble Tech Private Limited",
    "1402": "OMNI Remotes",
    "1403": "Duracell U.S. Operations Inc.",
    "1404": "Toor Technologies LLC",
    "1405": "Instinct Performance",
    "1406": "Beco, Inc",
    "1407": "Scuf Gaming International, LLC",
    "1408": "ARANZ Medical Limited",
    "1409": "LYS TECHNOLOGIES LTD",
    "1410": "Breakwall Analytics, LLC",
    "1411": "Code Blue Communications",
    "1412": "Gira Giersiepen GmbH & Co. KG",
    "1413": "Hearing Lab Technology",
    "1414": "LEGRAND",
    "1415": "Derichs GmbH",
    "1416": "ALT-TEKNIK LLC",
    "1417": "Star Technologies",
    "1418": "START TODAY CO.,LTD.",
    "1419": "Maxim Integrated Products",
    "1420": "MERCK Kommanditgesellschaft auf Aktien",
    "1421": "Jungheinrich Aktiengesellschaft",
    "1422": "Oculus VR, LLC",
    "1423": "HENDON SEMICONDUCTORS PTY LTD",
    "1424": "Pur3 Ltd",
    "1425": "Viasat Group S.p.A.",
    "1426": "IZITHERM",
    "1427": "Spaulding Clinical Research",
    "1428": "Kohler Company",
    "1429": "Inor Process AB",
    "1430": "My Smart Blinds",
    "1431": "RadioPulse Inc",
    "1432": "rapitag GmbH",
    "1433": "Lazlo326, LLC.",
    "1434": "Teledyne Lecroy, Inc.",
    "1435": "Dataflow Systems Limited",
    "1436": "Macrogiga Electronics",
    "1437": "Tandem Diabetes Care",
    "1438": "Polycom, Inc.",
    "1439": "Fisher & Paykel Healthcare",
    "1440": "RCP Software Oy",
    "1441": "Shanghai Xiaoyi Technology Co.,Ltd.",
    "1442": "ADHERIUM(NZ) LIMITED",
    "1443": "Axiomware Systems Incorporated",
    "1444": "O. E. M. Controls, Inc.",
    "1445": "Kiiroo BV",
    "1446": "Telecon Mobile Limited",
    "1447": "Sonos Inc",
    "1448": "Tom Allebrandi Consulting",
    "1449": "Monidor",
    "1450": "Tramex Limited",
    "1451": "Nofence AS",
    "1452": "GoerTek Dynaudio Co., Ltd.",
    "1453": "INIA",
    "1454": "CARMATE MFG.CO.,LTD",
    "1455": "ONvocal",
    "1456": "NewTec GmbH",
    "1457": "Medallion Instrumentation Systems",
    "1458": "CAREL INDUSTRIES S.P.A.",
    "1459": "Parabit Systems, Inc.",
    "1460": "White Horse Scientific ltd",
    "1461": "verisilicon",
    "1462": "Elecs Industry Co.,Ltd.",
    "1463": "Beijing Pinecone Electronics Co.,Ltd.",
    "1464": "Ambystoma Labs Inc.",
    "1465": "Suzhou Pairlink Network Technology",
    "1466": "igloohome",
    "1467": "Oxford Metrics plc",
    "1468": "Leviton Mfg. Co., Inc.",
    "1469": "ULC Robotics Inc.",
    "1470": "RFID Global by Softwork SrL",
    "1471": "Real-World-Systems Corporation",
    "1472": "Nalu Medical, Inc.",
    "1473": "P.I.Engineering",
    "1474": "Grote Industries",
    "1475": "Runtime, Inc.",
    "1476": "Codecoup sp. z o.o. sp. k.",
    "1477": "SELVE GmbH & Co. KG",
    "1478": "Smart Animal Training Systems, LLC",
    "1479": "Lippert Components, INC",
    "1480": "SOMFY SAS",
    "1481": "TBS Electronics B.V.",
    "1482": "MHL Custom Inc",
    "1483": "LucentWear LLC",
    "1484": "WATTS ELECTRONICS",
    "1485": "RJ Brands LLC",
    "1486": "V-ZUG Ltd",
    "1487": "Biowatch SA",
    "1488": "Anova Applied Electronics",
    "1489": "Lindab AB",
    "1490": "frogblue TECHNOLOGY GmbH",
    "1491": "Acurable Limited",
    "1492": "LAMPLIGHT Co., Ltd.",
    "1493": "TEGAM, Inc.",
    "1494": "Zhuhai Jieli technology Co.,Ltd",
    "1495": "modum.io AG",
    "1496": "Farm Jenny LLC",
    "1497": "Toyo Electronics Corporation",
    "1498": "Applied Neural Research Corp",
    "1499": "Avid Identification Systems, Inc.",
    "1500": "Petronics Inc.",
    "1501": "essentim GmbH",
    "1502": "QT Medical INC.",
    "1503": "VIRTUALCLINIC.DIRECT LIMITED",
    "1504": "Viper Design LLC",
    "1505": "Human, Incorporated",
    "1506": "stAPPtronics GmbH",
    "1507": "Elemental Machines, Inc.",
    "1508": "Taiyo Yuden Co., Ltd",
    "1509": "INEO ENERGY& SYSTEMS",
    "1510": "Motion Instruments Inc.",
    "1511": "PressurePro",
    "1512": "COWBOY",
    "1513": "iconmobile GmbH",
    "1514": "ACS-Control-System GmbH",
    "1515": "Bayerische Motoren Werke AG",
    "1516": "Gycom Svenska AB",
    "1517": "Fuji Xerox Co., Ltd",
    "1518": "Glide Inc.",
    "1519": "SIKOM AS",
    "1520": "beken",
    "1521": "The Linux Foundation",
    "1522": "Try and E CO.,LTD.",
    "1523": "SeeScan",
    "1524": "Clearity, LLC",
    "1525": "GS TAG",
    "1526": "DPTechnics",
    "1527": "TRACMO, INC.",
    "1528": "Anki Inc.",
    "1529": "Hagleitner Hygiene International GmbH",
    "1530": "Konami Sports Life Co., Ltd.",
    "1531": "Arblet Inc.",
    "1532": "Masbando GmbH",
    "1533": "Innoseis",
    "1534": "Niko",
    "1535": "Wellnomics Ltd",
    "1536": "iRobot Corporation",
    "1537": "Schrader Electronics",
    "1538": "Geberit International AG",
    "1539": "Fourth Evolution Inc",
    "1540": "Cell2Jack LLC",
    "1541": "FMW electronic Futterer u. Maier-Wolf OHG",
    "1542": "John Deere",
    "1543": "Rookery Technology Ltd",
    "1544": "KeySafe-Cloud",
    "1545": "BUCHI Labortechnik AG",
    "1546": "IQAir AG",
    "1547": "Triax Technologies Inc",
    "1548": "Vuzix Corporation",
    "1549": "TDK Corporation",
    "1550": "Blueair AB",
    "1551": "Philips Lighting B.V.",
    "1552": "ADH GUARDIAN USA LLC",
    "1553": "Beurer GmbH",
    "1554": "Playfinity AS",
    "1555": "Hans Dinslage GmbH",
    "1556": "OnAsset Intelligence, Inc.",
    "1557": "INTER ACTION Corporation",
    "1558": "OS42 UG (haftungsbeschraenkt)",
    "1559": "WIZCONNECTED COMPANY LIMITED",
    "1560": "Audio-Technica Corporation",
    "1561": "Six Guys Labs, s.r.o.",
    "1562": "R.W. Beckett Corporation",
    "1563": "silex technology, inc.",
    "1564": "Univations Limited",
    "1565": "SENS Innovation ApS",
    "1566": "Diamond Kinetics, Inc.",
    "1567": "Phrame Inc.",
    "1568": "Forciot Oy",
    "1569": "Noordung d.o.o.",
    "1570": "Beam Labs, LLC",
    "1571": "Philadelphia Scientific (U.K.) Limited",
    "1572": "Biovotion AG",
    "1573": "Square Panda, Inc.",
    "1574": "Amplifico",
    "1575": "WEG S.A.",
    "1576": "Ensto Oy",
    "1577": "PHONEPE PVT LTD",
    "1578": "Lunatico Astronomia SL",
    "1579": "MinebeaMitsumi Inc.",
    "1580": "ASPion GmbH",
    "1581": "Vossloh-Schwabe Deutschland GmbH",
    "1582": "Procept",
    "1583": "ONKYO Corporation",
    "1584": "Asthrea D.O.O.",
    "1585": "Fortiori Design LLC",
    "1586": "Hugo Muller GmbH & Co KG",
    "1587": "Wangi Lai PLT",
    "1588": "Fanstel Corp",
    "1589": "Crookwood"
}

